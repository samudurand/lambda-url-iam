import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as lambdaNode from 'aws-cdk-lib/aws-lambda-nodejs';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import path = require('path');
import { Effect, PolicyStatement } from 'aws-cdk-lib/aws-iam';

export class CdkStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

        // Create the Lambda
        const simpleLambda = new lambdaNode.NodejsFunction(this, 'simpleLambda', {
            entry: 'lambda/handler.ts',
            handler: 'handler',
            runtime: lambda.Runtime.NODEJS_18_X,
            functionName: 'simpleLambda'
        });

        const authFunction = this.createAuthEdgeFunction(simpleLambda.functionArn);

        // Configure the Lambda URL
        const lambdaUrl = simpleLambda.addFunctionUrl({
            authType: lambda.FunctionUrlAuthType.AWS_IAM,
        });

        // Create the CloudFront distribution redirecting calls to the Lambda URL
        const cfDistribution = new cloudfront.CloudFrontWebDistribution(this, 'CFDistribution', {
            originConfigs: [
                {
                    customOriginSource: {
                        domainName: this.getURLDomain(lambdaUrl),
                        originProtocolPolicy: cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
                    },
                    behaviors: [{
                        isDefaultBehavior: true,
                        allowedMethods: cloudfront.CloudFrontAllowedMethods.ALL,
                        lambdaFunctionAssociations: [{
                            eventType: cloudfront.LambdaEdgeEventType.ORIGIN_REQUEST,
                            lambdaFunction: authFunction.currentVersion,
                            includeBody: true
                        }],
                    }],
                }
            ],
        });

        const userPool = new cognito.UserPool(this, 'UserPool', {
            userPoolName: 'UserPool',
            selfSignUpEnabled: false,
            signInAliases: {
                email: true,
            },
            autoVerify: { email: true },
            passwordPolicy: {
                minLength: 8,
                requireLowercase: true,
                requireUppercase: true,
                requireDigits: true,
                requireSymbols: true,
            },
            accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
            deletionProtection: false,
            removalPolicy: cdk.RemovalPolicy.DESTROY,
        });

        const userPoolDomain = new cognito.CfnUserPoolDomain(this, 'UserPoolDomain', {
            domain: `000011114444-iam-login`,
            userPoolId: userPool.userPoolId,
        });

        const poolHostedUIUrl = `https://${userPoolDomain.domain}.auth.${this.region}.amazoncognito.com`;

        const userPoolClient = new cognito.UserPoolClient(this, 'UserPoolClient', {
            userPool,
            authFlows: {
                adminUserPassword: true,
            },
            generateSecret: false,
            oAuth: {
              flows: {
                implicitCodeGrant: true,
              },
              scopes: [
                cognito.OAuthScope.OPENID,
                cognito.OAuthScope.PROFILE,
              ],
              callbackUrls: [poolHostedUIUrl],
              logoutUrls: [poolHostedUIUrl],
            },
        });

        const poolHostedUIUrlWithParameters = `${poolHostedUIUrl}/login?client_id=${userPoolClient.userPoolClientId}&response_type=token&scope=openid+profile&redirect_uri=${encodeURIComponent(poolHostedUIUrl)}`;

        // Store User Pool Client ID in SSM Parameter Store and allow the edge function access
        
        const userPoolIdParam = new ssm.StringParameter(this, 'UserPoolIdParam', {
            parameterName: '/lambda-url-iam/user-pool-id',
            stringValue: userPool.userPoolId,
        });

        const userPoolClientIdParam = new ssm.StringParameter(this, 'UserPoolClientIdParam', {
            parameterName: '/lambda-url-iam/user-pool-client-id',
            stringValue: userPoolClient.userPoolClientId,
        });

        authFunction.addToRolePolicy(new PolicyStatement({
            effect: Effect.ALLOW,
            actions: ['ssm:GetParameter'],
            resources: [
                userPoolIdParam.parameterArn,
                userPoolClientIdParam.parameterArn,
            ],
        }));

        new cdk.CfnOutput(this, 'CognitoUIUrl', {
            value: poolHostedUIUrl,
        });
        new cdk.CfnOutput(this, 'CognitoUIUrlWithParameters', {
            value: poolHostedUIUrlWithParameters,
        });
        new cdk.CfnOutput(this, 'CognitoUserPoolClientId', {
            value: userPoolClient.userPoolClientId,
        });
        new cdk.CfnOutput(this, 'CloudFrontDistributionURL', {
            value: `https://${cfDistribution.distributionDomainName}`,
        });

    }

    /**
     * Extracts the domain from a Lambda URL
     * 
     * Example: https://my-lambda.execute-api.us-east-1.amazonaws.com/ -> my-lambda.execute-api.us-east-1.amazonaws.com
     */
    getURLDomain(lambdaUrl: lambda.FunctionUrl) {
        return cdk.Fn.select(2, cdk.Fn.split('/', lambdaUrl.url));
    }

    private createAuthEdgeFunction(functionArn: string) {
        const authFunction = new cloudfront.experimental.EdgeFunction(this, 'AuthLambdaEdge', {
            handler: 'authEdge.handler',
            runtime: lambda.Runtime.NODEJS_16_X,
            code: lambda.Code.fromAsset(path.join(__dirname, '../lambda-edge'), {
                bundling: {
                    command: [
                        "bash",
                        "-c",
                        "npm install && cp -rT /asset-input/ /asset-output/",
                    ],
                    image: lambda.Runtime.NODEJS_16_X.bundlingImage,
                    user: "root",
                },
            }),
            currentVersionOptions: {
                removalPolicy: cdk.RemovalPolicy.DESTROY
            },
            timeout: cdk.Duration.seconds(7),
        });

        authFunction.addToRolePolicy(new PolicyStatement({
            sid: 'AllowInvokeFunctionUrl',
            effect: Effect.ALLOW,
            actions: ['lambda:InvokeFunctionUrl'],
            resources: [functionArn],
            conditions: {
                "StringEquals": { "lambda:FunctionUrlAuthType": "AWS_IAM" }
            }
        }));
        return authFunction;
    }
}
