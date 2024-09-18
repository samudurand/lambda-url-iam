const axios = require('axios');
const { SignatureV4 } = require('@aws-sdk/signature-v4');
const { Sha256 } = require('@aws-crypto/sha256-js');
const { CognitoJwtVerifier } = require('aws-jwt-verify');
const { SSMClient, GetParameterCommand } = require('@aws-sdk/client-ssm');

const {
    AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY,
    AWS_SESSION_TOKEN,
} = process.env;


const ssmClient = new SSMClient();

const getParameter = async (name) => {
    const command = new GetParameterCommand({ Name: name });
    const response = await ssmClient.send(command);
    return response.Parameter.Value;
};

const sigv4 = new SignatureV4({
    service: 'lambda',
    region: 'eu-central-1',
    credentials: {
        accessKeyId: AWS_ACCESS_KEY_ID,
        secretAccessKey: AWS_SECRET_ACCESS_KEY,
        sessionToken: AWS_SESSION_TOKEN,
    },
    sha256: Sha256,
});

module.exports.handler = async (event) => {
    const cfRequest = event.Records[0].cf.request;

    let headers = cfRequest.headers;

    // Check for the authorization header
    const authHeader = headers['authorization'];
    if (!authHeader || !authHeader[0] || !authHeader[0].value.startsWith('Bearer ')) {
        return {
            status: '403',
            statusDescription: 'Forbidden',
            body: 'Unauthorized',
        };
    }

    const token = authHeader[0].value.split(' ')[1];

    // Verify the token with Cognito
    try {
        const COGNITO_USER_POOL_ID = await getParameter('/publisher/user-pool-id');
        const COGNITO_CLIENT_ID = await getParameter('/publisher/user-pool-client-id');

        const verifier = CognitoJwtVerifier.create({
            userPoolId: COGNITO_USER_POOL_ID,
            tokenUse: "id",
            clientId: COGNITO_CLIENT_ID,
        });

        await verifier.verify(token);
    } catch (err) {
        console.error('Token verification failed:', err);
        return {
            status: '403',
            statusDescription: 'Forbidden',
            body: 'Unauthorized',
        };
    }

    const apiUrl = new URL(`https://${cfRequest.origin.custom.domainName}${cfRequest.uri}`);

    const signV4Options = {
        method: cfRequest.method,
        hostname: apiUrl.host,
        path: apiUrl.pathname + (cfRequest.querystring ? `?${cfRequest.querystring}` : ''),
        protocol: apiUrl.protocol,
        query: cfRequest.querystring,
        headers: {
            'Content-Type': headers['content-type'][0].value,
            host: apiUrl.hostname, // compulsory
        },
    };

    try {
        return await signAndForwardRequest(cfRequest, signV4Options, apiUrl);
    } catch (error) {
        console.error('An error occurred', error);
        return {
            status: '500',
            statusDescription: 'Internal Server Error',
            body: 'Internal Server Error',
        };
    }
};

async function signAndForwardRequest(cfRequest, signV4Options, apiUrl) {
    if (cfRequest.body && cfRequest.body.data) {
        let body = cfRequest.body.data;
        if (cfRequest.body.encoding === 'base64') {
            body = Buffer.from(body, 'base64').toString('utf-8');
        }

        signV4Options.body = typeof body === 'string' ? body : JSON.stringify(body);
        signV4Options.headers['Content-Length'] = Buffer.byteLength(signV4Options.body).toString();
    }

    const signed = await sigv4.sign(signV4Options);
    const result = await axios({
        ...signed,
        url: apiUrl.href,
        timeout: 5000,
        data: signV4Options.body,
    });

    return {
        status: '200',
        statusDescription: 'OK',
        body: JSON.stringify(result.data),
    };
}

