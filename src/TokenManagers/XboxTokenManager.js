const crypto = require('crypto');
const { xnet, live } = require('@xboxreplay/xboxlive-auth');
const debug = require('debug')('prismarine-auth');
const { SmartBuffer } = require('smart-buffer');

const { Endpoints, xboxLiveErrors } = require('../common/Constants');
const { checkStatus, createHash } = require('../common/Util');

const UUID = require('uuid-1345');
const nextUUID = () =>
  UUID.v3({ namespace: '6ba7b811-9dad-11d1-80b4-00c04fd430c8', name: Date.now().toString() });

const checkIfValid = (expires) => {
  const remainingMs = new Date(expires) - Date.now();
  const valid = remainingMs > 1000;
  return valid;
};

// Manages Xbox Live tokens for xboxlive.com
class XboxTokenManager {
  constructor(ecKey, cache) {
    this.key = ecKey;
    this.jwk = { ...ecKey.publicKey.export({ format: 'jwk' }), alg: 'ES256', use: 'sig' };
    this.cache = cache;

    this.headers = {
      'Cache-Control': 'no-store, must-revalidate, no-cache',
      'x-xbl-contract-version': 1,
    };
  }

  async setCachedToken(data) {
    await this.cache.setCachedPartial(data);
  }

  async getCachedTokens(relyingParty) {
    const cachedTokens = await this.cache.getCached();

    const xstsHash = createHash(relyingParty);

    const result = {};

    for (const token of ['userToken', 'titleToken', 'deviceToken']) {
      const cached = cachedTokens[token];
      result[token] =
        cached && checkIfValid(cached.NotAfter)
          ? { valid: true, token: cached.Token, data: cached }
          : { valid: false };
    }
    result.xstsToken =
      cachedTokens[xstsHash] && checkIfValid(cachedTokens[xstsHash].expiresOn)
        ? { valid: true, data: cachedTokens[xstsHash] }
        : { valid: false };

    return result;
  }

  checkTokenError(errorCode, response) {
    if (errorCode in xboxLiveErrors)
      throw new Error(xboxLiveErrors[errorCode]);
    else
      throw new Error(
        `Xbox Live authentication failed to obtain a XSTS token. XErr: ${errorCode}\n${JSON.stringify(
          response
        )}`
      );
  }

  // Signature method unchanged; keeps your signing logic as is
  sign(url, authorizationToken, payload) {
    const windowsTimestamp =
      (BigInt((Date.now() / 1000) | 0) + 11644473600n) * 10000000n;
    const pathAndQuery = new URL(url).pathname;

    const allocSize =
      /* sig */ 5 +
      /* ts */ 9 +
      /* POST */ 5 +
      pathAndQuery.length +
      1 +
      authorizationToken.length +
      1 +
      payload.length +
      1;
    const buf = SmartBuffer.fromSize(allocSize);
    buf.writeInt32BE(1);
    buf.writeUInt8(0);
    buf.writeBigUInt64BE(windowsTimestamp);
    buf.writeUInt8(0);
    buf.writeStringNT('POST');
    buf.writeStringNT(pathAndQuery);
    buf.writeStringNT(authorizationToken);
    buf.writeStringNT(payload);

    const signature = crypto.sign('SHA256', buf.toBuffer(), {
      key: this.key.privateKey,
      dsaEncoding: 'ieee-p1363',
    });

    const header = SmartBuffer.fromSize(signature.length + 12);
    header.writeInt32BE(1);
    header.writeBigUInt64BE(windowsTimestamp);
    header.writeBuffer(signature);

    return header.toBuffer();
  }

  // Updated to use live.authenticate() and xnet.exchangeTokensForXSTSToken()
  async doReplayAuth(email, password, options = {}) {
    try {
      // Authenticate with Microsoft Account credentials (returns raw responses)
      const authResponse = await live.authenticate(email, password, { raw: true });

      // Extract user token from the response
      const userTokenResponse = authResponse['user.auth.xboxlive.com'];

      await this.setCachedToken({ userToken: userTokenResponse });
      debug('[xbl] user token:', userTokenResponse);

      // Exchange user token for XSTS token using new API
      const xsts = await xnet.exchangeTokensForXSTSToken(
        { userTokens: [userTokenResponse.Token] },
        {
          XSTSRelyingParty: options.relyingParty,
          optionalDisplayClaims: options.optionalDisplayClaims,
          sandboxId: options.sandboxId,
        }
      );

      await this.setCachedToken({ [createHash(options.relyingParty)]: xsts });
      debug('[xbl] xsts', xsts);

      return xsts;
    } catch (error) {
      debug('Authentication using a password has failed.');
      debug(error);
      throw error;
    }
  }

  // Keep your existing doSisuAuth logic (you can update it similarly if you want)

  // Updated getXSTSToken to use xnet.exchangeTokensForXSTSToken
  async getXSTSToken(tokens, options = {}) {
    debug('[xbl] obtaining xsts token', {
      userToken: tokens.userToken,
      deviceToken: tokens.deviceToken,
      titleToken: tokens.titleToken,
    });

    const XSTSResponse = await xnet.exchangeTokensForXSTSToken(
      {
        userTokens: [tokens.userToken],
        deviceToken: tokens.deviceToken,
        titleToken: tokens.titleToken,
      },
      {
        XSTSRelyingParty: options.relyingParty,
        optionalDisplayClaims: options.optionalDisplayClaims,
        sandboxId: options.sandboxId,
      }
    );

    await this.setCachedToken({ [createHash(options.relyingParty)]: XSTSResponse });

    debug('[xbl] xsts', XSTSResponse);
    return XSTSResponse;
  }

  // Other methods remain mostly unchanged but you can consider switching to xnet methods as needed

  // Example: getUserToken could use xnet.exchangeRpsTicketForUserToken if you want to keep it:
  async getUserToken(accessToken, azure) {
    debug('[xbl] obtaining xbox token with ms token', accessToken);
    const preamble = azure ? 'd=' : 't=';

    const userToken = await xnet.exchangeRpsTicketForUserToken(`${preamble}${accessToken}`);
    await this.setCachedToken({ userToken });
    debug('[xbl] user token:', userToken);
    return userToken.Token;
  }
}

module.exports = XboxTokenManager;
