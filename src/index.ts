// @fluxpointstudios/cip30-deeplink-client — dApp-side reference SDK for CIP-30-DeepLink
// (cardano-foundation/CIPs#1189). Companion to the Yuti reference wallet.

export { DeepLinkClient, type ResumeResult } from './client.js';
export {
  DeepLinkRejection,
  type ChainId,
  type DappInfo,
  type DeepLinkClientOptions,
  type KeyValueStore,
  type Session,
  type SignFormat,
  type SignTxOptions,
  type SignTxResult,
} from './types.js';

// Low-level wire helpers — for custom transports, server-side use, or testing.
export {
  PROTOCOL_VERSION,
  buildConnectUrl,
  buildSignTxUrl,
  bytesToHex,
  decodeConnectResponse,
  decodeSignTxResponse,
  endpointBase,
  hexToBytes,
  isResponseUrl,
  throwIfRejected,
  walletScheme,
  type ConnectUrlParams,
  type SignTxUrlParams,
} from './protocol.js';
export {
  canonicalSubject,
  canonicalSubjectCandidates,
  SUBJECT_DOMAIN_SEPARATOR,
} from './canonical.js';
export { b64uDecode, b64uEncode } from './base64url.js';
