/* eslint-disable */
// sequence-waas-intents v0.1.0 97c26d28120d42589f65e661f1f2bc376f3872ed
// --
// Code generated by webrpc-gen@v0.15.5 with typescript generator. DO NOT EDIT.
//
// webrpc-gen -schema=intent.ridl -target=typescript -client -out=./intent.gen.ts

// WebRPC description and code-gen version
export const WebRPCVersion = "v1"

// Schema version of your RIDL schema
export const WebRPCSchemaVersion = "v0.1.0"

// Schema hash generated from your RIDL schema
export const WebRPCSchemaHash = "97c26d28120d42589f65e661f1f2bc376f3872ed"

//
// Types
//


export enum IntentName {
  openSession = 'openSession',
  closeSession = 'closeSession',
  validateSession = 'validateSession',
  finishValidateSession = 'finishValidateSession',
  listSessions = 'listSessions',
  getSession = 'getSession',
  sessionAuthProof = 'sessionAuthProof',
  feeOptions = 'feeOptions',
  signMessage = 'signMessage',
  sendTransaction = 'sendTransaction',
  getTransactionReceipt = 'getTransactionReceipt',
  federateAccount = 'federateAccount',
  removeAccount = 'removeAccount',
  listAccounts = 'listAccounts'
}

export enum TransactionType {
  transaction = 'transaction',
  erc20send = 'erc20send',
  erc721send = 'erc721send',
  erc1155send = 'erc1155send',
  delayedEncode = 'delayedEncode'
}

export enum IntentResponseCode {
  sessionOpened = 'sessionOpened',
  sessionClosed = 'sessionClosed',
  sessionList = 'sessionList',
  validationRequired = 'validationRequired',
  validationStarted = 'validationStarted',
  validationFinished = 'validationFinished',
  sessionAuthProof = 'sessionAuthProof',
  signedMessage = 'signedMessage',
  feeOptions = 'feeOptions',
  transactionReceipt = 'transactionReceipt',
  transactionFailed = 'transactionFailed',
  getSessionResponse = 'getSessionResponse',
  accountList = 'accountList',
  accountFederated = 'accountFederated',
  accountRemoved = 'accountRemoved'
}

export enum FeeTokenType {
  unknown = 'unknown',
  erc20Token = 'erc20Token',
  erc1155Token = 'erc1155Token'
}

export enum IdentityType {
  None = 'None',
  Guest = 'Guest',
  OIDC = 'OIDC'
}

export interface Intent {
  version: string
  name: IntentName
  expiresAt: number
  issuedAt: number
  data: any
  signatures: Array<Signature>
}

export interface Signature {
  sessionId: string
  signature: string
}

export interface IntentDataOpenSession {
  sessionId: string
  email?: string
  idToken?: string
  forceCreateAccount?: boolean
}

export interface IntentDataCloseSession {
  sessionId: string
}

export interface IntentDataValidateSession {
  sessionId: string
  wallet: string
  deviceMetadata: string
}

export interface IntentDataFinishValidateSession {
  sessionId: string
  wallet: string
  salt: string
  challenge: string
}

export interface IntentDataListSessions {
  wallet: string
}

export interface IntentDataGetSession {
  sessionId: string
  wallet: string
}

export interface IntentDataSessionAuthProof {
  network: string
  wallet: string
  nonce?: string
}

export interface IntentDataSignMessage {
  network: string
  wallet: string
  message: string
}

export interface IntentDataFeeOptions {
  network: string
  wallet: string
  identifier: string
  transactions: Array<any>
}

export interface IntentDataSendTransaction {
  network: string
  wallet: string
  identifier: string
  transactions: Array<any>
  transactionsFeeQuote?: string
}

export interface IntentDataGetTransactionReceipt {
  network: string
  wallet: string
  metaTxHash: string
}

export interface IntentDataFederateAccount {
  sessionId: string
  wallet: string
  idToken: string
}

export interface IntentDataListAccounts {
  wallet: string
}

export interface IntentDataRemoveAccount {
  wallet: string
  accountId: string
}

export interface TransactionRaw {
  type: string
  to: string
  value: string
  data: string
}

export interface TransactionERC20 {
  type: string
  tokenAddress: string
  to: string
  value: string
}

export interface TransactionERC721 {
  type: string
  tokenAddress: string
  to: string
  id: string
  safe?: boolean
  data?: string
}

export interface TransactionERC1155Value {
  id: string
  amount: string
}

export interface TransactionDelayedEncode {
  type: string
  to: string
  value: string
  data: any
}

export interface TransactionERC1155 {
  type: string
  tokenAddress: string
  to: string
  vals: Array<TransactionERC1155Value>
  data?: string
}

export interface IntentResponse {
  code: IntentResponseCode
  data: any
}

export interface IntentResponseSessionOpened {
  sessionId: string
  wallet: string
}

export interface IntentResponseSessionClosed {
}

export interface IntentResponseValidateSession {
}

export interface IntentResponseValidationRequired {
  sessionId: string
}

export interface IntentResponseValidationStarted {
  salt: string
}

export interface IntentResponseValidationFinished {
  isValid: boolean
}

export interface IntentResponseListSessions {
  sessions: Array<string>
}

export interface IntentResponseGetSession {
  sessionId: string
  wallet: string
  validated: boolean
}

export interface IntentResponseSessionAuthProof {
  sessionId: string
  network: string
  wallet: string
  message: string
  signature: string
}

export interface IntentResponseSignedMessage {
  signature: string
  message: string
}

export interface FeeOption {
  token: FeeToken
  to: string
  value: string
  gasLimit: number
}

export interface FeeToken {
  chainId: number
  name: string
  symbol: string
  type: FeeTokenType
  decimals?: number
  logoURL: string
  contractAddress?: string
  tokenID?: string
}

export interface IntentResponseFeeOptions {
  feeOptions: Array<FeeOption>
  feeQuote?: string
}

export interface IntentResponseTransactionReceipt {
  request: any
  txHash: string
  metaTxHash: string
  receipt: any
  nativeReceipt: any
  simulations: any
}

export interface IntentResponseTransactionFailed {
  error: string
  request: any
  simulations: any
}

export interface IntentResponseAccountList {
  accounts: Array<Account>
}

export interface IntentResponseAccountFederated {
  account: Account
}

export interface IntentResponseAccountRemoved {
}

export interface Account {
  id: string
  type: IdentityType
  issuer: string
  email?: string
}

  

  const createHTTPRequest = (body: object = {}, headers: object = {}, signal: AbortSignal | null = null): object => {
  return {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
    signal
  }
}

const buildResponse = (res: Response): Promise<any> => {
  return res.text().then(text => {
    let data
    try {
      data = JSON.parse(text)
    } catch(error) {
      let message = ''
      if (error instanceof Error)  {
        message = error.message
      }
      throw WebrpcBadResponseError.new({
        status: res.status,
        cause: `JSON.parse(): ${message}: response text: ${text}`},
      )
    }
    if (!res.ok) {
      const code: number = (typeof data.code === 'number') ? data.code : 0
      throw (webrpcErrorByCode[code] || WebrpcError).new(data)
    }
    return data
  })
}

//
// Errors
//

export class WebrpcError extends Error {
  name: string
  code: number
  message: string
  status: number
  cause?: string

  /** @deprecated Use message instead of msg. Deprecated in webrpc v0.11.0. */
  msg: string

  constructor(name: string, code: number, message: string, status: number, cause?: string) {
    super(message)
    this.name = name || 'WebrpcError'
    this.code = typeof code === 'number' ? code : 0
    this.message = message || `endpoint error ${this.code}`
    this.msg = this.message
    this.status = typeof status === 'number' ? status : 0
    this.cause = cause
    Object.setPrototypeOf(this, WebrpcError.prototype)
  }

  static new(payload: any): WebrpcError {
    return new this(payload.error, payload.code, payload.message || payload.msg, payload.status, payload.cause)
  }
}

// Webrpc errors

export class WebrpcEndpointError extends WebrpcError {
  constructor(
    name: string = 'WebrpcEndpoint',
    code: number = 0,
    message: string = 'endpoint error',
    status: number = 0,
    cause?: string
  ) {
    super(name, code, message, status, cause)
    Object.setPrototypeOf(this, WebrpcEndpointError.prototype)
  }
}

export class WebrpcRequestFailedError extends WebrpcError {
  constructor(
    name: string = 'WebrpcRequestFailed',
    code: number = -1,
    message: string = 'request failed',
    status: number = 0,
    cause?: string
  ) {
    super(name, code, message, status, cause)
    Object.setPrototypeOf(this, WebrpcRequestFailedError.prototype)
  }
}

export class WebrpcBadRouteError extends WebrpcError {
  constructor(
    name: string = 'WebrpcBadRoute',
    code: number = -2,
    message: string = 'bad route',
    status: number = 0,
    cause?: string
  ) {
    super(name, code, message, status, cause)
    Object.setPrototypeOf(this, WebrpcBadRouteError.prototype)
  }
}

export class WebrpcBadMethodError extends WebrpcError {
  constructor(
    name: string = 'WebrpcBadMethod',
    code: number = -3,
    message: string = 'bad method',
    status: number = 0,
    cause?: string
  ) {
    super(name, code, message, status, cause)
    Object.setPrototypeOf(this, WebrpcBadMethodError.prototype)
  }
}

export class WebrpcBadRequestError extends WebrpcError {
  constructor(
    name: string = 'WebrpcBadRequest',
    code: number = -4,
    message: string = 'bad request',
    status: number = 0,
    cause?: string
  ) {
    super(name, code, message, status, cause)
    Object.setPrototypeOf(this, WebrpcBadRequestError.prototype)
  }
}

export class WebrpcBadResponseError extends WebrpcError {
  constructor(
    name: string = 'WebrpcBadResponse',
    code: number = -5,
    message: string = 'bad response',
    status: number = 0,
    cause?: string
  ) {
    super(name, code, message, status, cause)
    Object.setPrototypeOf(this, WebrpcBadResponseError.prototype)
  }
}

export class WebrpcServerPanicError extends WebrpcError {
  constructor(
    name: string = 'WebrpcServerPanic',
    code: number = -6,
    message: string = 'server panic',
    status: number = 0,
    cause?: string
  ) {
    super(name, code, message, status, cause)
    Object.setPrototypeOf(this, WebrpcServerPanicError.prototype)
  }
}

export class WebrpcInternalErrorError extends WebrpcError {
  constructor(
    name: string = 'WebrpcInternalError',
    code: number = -7,
    message: string = 'internal error',
    status: number = 0,
    cause?: string
  ) {
    super(name, code, message, status, cause)
    Object.setPrototypeOf(this, WebrpcInternalErrorError.prototype)
  }
}

export class WebrpcClientDisconnectedError extends WebrpcError {
  constructor(
    name: string = 'WebrpcClientDisconnected',
    code: number = -8,
    message: string = 'client disconnected',
    status: number = 0,
    cause?: string
  ) {
    super(name, code, message, status, cause)
    Object.setPrototypeOf(this, WebrpcClientDisconnectedError.prototype)
  }
}

export class WebrpcStreamLostError extends WebrpcError {
  constructor(
    name: string = 'WebrpcStreamLost',
    code: number = -9,
    message: string = 'stream lost',
    status: number = 0,
    cause?: string
  ) {
    super(name, code, message, status, cause)
    Object.setPrototypeOf(this, WebrpcStreamLostError.prototype)
  }
}

export class WebrpcStreamFinishedError extends WebrpcError {
  constructor(
    name: string = 'WebrpcStreamFinished',
    code: number = -10,
    message: string = 'stream finished',
    status: number = 0,
    cause?: string
  ) {
    super(name, code, message, status, cause)
    Object.setPrototypeOf(this, WebrpcStreamFinishedError.prototype)
  }
}


// Schema errors


export enum errors {
  WebrpcEndpoint = 'WebrpcEndpoint',
  WebrpcRequestFailed = 'WebrpcRequestFailed',
  WebrpcBadRoute = 'WebrpcBadRoute',
  WebrpcBadMethod = 'WebrpcBadMethod',
  WebrpcBadRequest = 'WebrpcBadRequest',
  WebrpcBadResponse = 'WebrpcBadResponse',
  WebrpcServerPanic = 'WebrpcServerPanic',
  WebrpcInternalError = 'WebrpcInternalError',
  WebrpcClientDisconnected = 'WebrpcClientDisconnected',
  WebrpcStreamLost = 'WebrpcStreamLost',
  WebrpcStreamFinished = 'WebrpcStreamFinished',
}

const webrpcErrorByCode: { [code: number]: any } = {
  [0]: WebrpcEndpointError,
  [-1]: WebrpcRequestFailedError,
  [-2]: WebrpcBadRouteError,
  [-3]: WebrpcBadMethodError,
  [-4]: WebrpcBadRequestError,
  [-5]: WebrpcBadResponseError,
  [-6]: WebrpcServerPanicError,
  [-7]: WebrpcInternalErrorError,
  [-8]: WebrpcClientDisconnectedError,
  [-9]: WebrpcStreamLostError,
  [-10]: WebrpcStreamFinishedError,
}

export type Fetch = (input: RequestInfo, init?: RequestInit) => Promise<Response>

