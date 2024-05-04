/* eslint-disable */
// sequence-waas-authenticator v0.1.0 910d56700416894adba15fca1fcf1319bbda2b33
// --
// Code generated by webrpc-gen@v0.18.6 with typescript generator. DO NOT EDIT.
//
// webrpc-gen -schema=authenticator.ridl -target=typescript -client -out=./clients/authenticator.gen.ts

// WebRPC description and code-gen version
export const WebRPCVersion = "v1"

// Schema version of your RIDL schema
export const WebRPCSchemaVersion = "v0.1.0"

// Schema hash generated from your RIDL schema
export const WebRPCSchemaHash = "910d56700416894adba15fca1fcf1319bbda2b33"

//
// Types
//


export interface Intent {
  version: string
  name: string
  expiresAt: number
  issuedAt: number
  data: any
  signatures: Array<Signature>
}

export interface Signature {
  sessionId: string
  signature: string
}

export interface IntentResponse {
  code: string
  data: any
}

export enum IdentityType {
  None = 'None',
  Guest = 'Guest',
  OIDC = 'OIDC'
}

export interface Version {
  webrpcVersion: string
  schemaVersion: string
  schemaHash: string
  appVersion: string
}

export interface RuntimeStatus {
  healthOK: boolean
  startTime: string
  uptime: number
  ver: string
  pcr0: string
}

export interface Chain {
  id: number
  name: string
  isEnabled: boolean
}

export interface Identity {
  type: IdentityType
  iss: string
  sub: string
  email: string
}

export interface OpenIdProvider {
  iss: string
  aud: Array<string>
}

export interface Tenant {
  projectId: number
  version: number
  oidcProviders: Array<OpenIdProvider>
  allowedOrigins: Array<string>
  updatedAt: string
}

export interface TenantData {
  projectId: number
  privateKey: string
  parentAddress: string
  userSalt: string
  sequenceContext: MiniSequenceContext
  upgradeCode: string
  waasAccessToken: string
  oidcProviders: Array<OpenIdProvider>
  kmsKeys: Array<string>
  allowedOrigins: Array<string>
}

export interface MiniSequenceContext {
  factory: string
  mainModule: string
}

export interface AccountData {
  projectId: number
  userId: string
  identity: string
  createdAt: string
}

export interface Session {
  id: string
  projectId: number
  userId: string
  identity: Identity
  friendlyName: string
  createdAt: string
  refreshedAt: string
  expiresAt: string
}

export interface SessionData {
  id: string
  projectId: number
  userId: string
  identity: string
  createdAt: string
  expiresAt: string
}

export interface WaasAuthenticator {
  registerSession(args: RegisterSessionArgs, headers?: object, signal?: AbortSignal): Promise<RegisterSessionReturn>
  sendIntent(args: SendIntentArgs, headers?: object, signal?: AbortSignal): Promise<SendIntentReturn>
  chainList(headers?: object, signal?: AbortSignal): Promise<ChainListReturn>
}

export interface RegisterSessionArgs {
  intent: Intent
  friendlyName: string
}

export interface RegisterSessionReturn {
  session: Session
  response: IntentResponse  
}
export interface SendIntentArgs {
  intent: Intent
}

export interface SendIntentReturn {
  response: IntentResponse  
}
export interface ChainListArgs {
}

export interface ChainListReturn {
  chains: Array<Chain>  
}

export interface WaasAuthenticatorAdmin {
  version(headers?: object, signal?: AbortSignal): Promise<VersionReturn>
  runtimeStatus(headers?: object, signal?: AbortSignal): Promise<RuntimeStatusReturn>
  clock(headers?: object, signal?: AbortSignal): Promise<ClockReturn>
  getTenant(args: GetTenantArgs, headers?: object, signal?: AbortSignal): Promise<GetTenantReturn>
  createTenant(args: CreateTenantArgs, headers?: object, signal?: AbortSignal): Promise<CreateTenantReturn>
  updateTenant(args: UpdateTenantArgs, headers?: object, signal?: AbortSignal): Promise<UpdateTenantReturn>
}

export interface VersionArgs {
}

export interface VersionReturn {
  version: Version  
}
export interface RuntimeStatusArgs {
}

export interface RuntimeStatusReturn {
  status: RuntimeStatus  
}
export interface ClockArgs {
}

export interface ClockReturn {
  serverTime: string  
}
export interface GetTenantArgs {
  projectId: number
}

export interface GetTenantReturn {
  tenant: Tenant  
}
export interface CreateTenantArgs {
  projectId: number
  waasAccessToken: string
  oidcProviders: Array<OpenIdProvider>
  allowedOrigins: Array<string>
  password?: string
}

export interface CreateTenantReturn {
  tenant: Tenant
  upgradeCode: string  
}
export interface UpdateTenantArgs {
  projectId: number
  upgradeCode: string
  oidcProviders: Array<OpenIdProvider>
  allowedOrigins: Array<string>
}

export interface UpdateTenantReturn {
  tenant: Tenant  
}


  
//
// Client
//
export class WaasAuthenticator implements WaasAuthenticator {
  protected hostname: string
  protected fetch: Fetch
  protected path = '/rpc/WaasAuthenticator/'

  constructor(hostname: string, fetch: Fetch) {
    this.hostname = hostname
    this.fetch = (input: RequestInfo, init?: RequestInit) => fetch(input, init)
  }

  private url(name: string): string {
    return this.hostname + this.path + name
  }
  
  registerSession = (args: RegisterSessionArgs, headers?: object, signal?: AbortSignal): Promise<RegisterSessionReturn> => {
    return this.fetch(
      this.url('RegisterSession'),
      createHTTPRequest(args, headers, signal)).then((res) => {
      return buildResponse(res).then(_data => {
        return {
          session: <Session>(_data.session),
          response: <IntentResponse>(_data.response),
        }
      })
    }, (error) => {
      throw WebrpcRequestFailedError.new({ cause: `fetch(): ${error.message || ''}` })
    })
  }
  
  sendIntent = (args: SendIntentArgs, headers?: object, signal?: AbortSignal): Promise<SendIntentReturn> => {
    return this.fetch(
      this.url('SendIntent'),
      createHTTPRequest(args, headers, signal)).then((res) => {
      return buildResponse(res).then(_data => {
        return {
          response: <IntentResponse>(_data.response),
        }
      })
    }, (error) => {
      throw WebrpcRequestFailedError.new({ cause: `fetch(): ${error.message || ''}` })
    })
  }
  
  chainList = (headers?: object, signal?: AbortSignal): Promise<ChainListReturn> => {
    return this.fetch(
      this.url('ChainList'),
      createHTTPRequest({}, headers, signal)
      ).then((res) => {
      return buildResponse(res).then(_data => {
        return {
          chains: <Array<Chain>>(_data.chains),
        }
      })
    }, (error) => {
      throw WebrpcRequestFailedError.new({ cause: `fetch(): ${error.message || ''}` })
    })
  }
  
}
export class WaasAuthenticatorAdmin implements WaasAuthenticatorAdmin {
  protected hostname: string
  protected fetch: Fetch
  protected path = '/rpc/WaasAuthenticatorAdmin/'

  constructor(hostname: string, fetch: Fetch) {
    this.hostname = hostname
    this.fetch = (input: RequestInfo, init?: RequestInit) => fetch(input, init)
  }

  private url(name: string): string {
    return this.hostname + this.path + name
  }
  
  version = (headers?: object, signal?: AbortSignal): Promise<VersionReturn> => {
    return this.fetch(
      this.url('Version'),
      createHTTPRequest({}, headers, signal)
      ).then((res) => {
      return buildResponse(res).then(_data => {
        return {
          version: <Version>(_data.version),
        }
      })
    }, (error) => {
      throw WebrpcRequestFailedError.new({ cause: `fetch(): ${error.message || ''}` })
    })
  }
  
  runtimeStatus = (headers?: object, signal?: AbortSignal): Promise<RuntimeStatusReturn> => {
    return this.fetch(
      this.url('RuntimeStatus'),
      createHTTPRequest({}, headers, signal)
      ).then((res) => {
      return buildResponse(res).then(_data => {
        return {
          status: <RuntimeStatus>(_data.status),
        }
      })
    }, (error) => {
      throw WebrpcRequestFailedError.new({ cause: `fetch(): ${error.message || ''}` })
    })
  }
  
  clock = (headers?: object, signal?: AbortSignal): Promise<ClockReturn> => {
    return this.fetch(
      this.url('Clock'),
      createHTTPRequest({}, headers, signal)
      ).then((res) => {
      return buildResponse(res).then(_data => {
        return {
          serverTime: <string>(_data.serverTime),
        }
      })
    }, (error) => {
      throw WebrpcRequestFailedError.new({ cause: `fetch(): ${error.message || ''}` })
    })
  }
  
  getTenant = (args: GetTenantArgs, headers?: object, signal?: AbortSignal): Promise<GetTenantReturn> => {
    return this.fetch(
      this.url('GetTenant'),
      createHTTPRequest(args, headers, signal)).then((res) => {
      return buildResponse(res).then(_data => {
        return {
          tenant: <Tenant>(_data.tenant),
        }
      })
    }, (error) => {
      throw WebrpcRequestFailedError.new({ cause: `fetch(): ${error.message || ''}` })
    })
  }
  
  createTenant = (args: CreateTenantArgs, headers?: object, signal?: AbortSignal): Promise<CreateTenantReturn> => {
    return this.fetch(
      this.url('CreateTenant'),
      createHTTPRequest(args, headers, signal)).then((res) => {
      return buildResponse(res).then(_data => {
        return {
          tenant: <Tenant>(_data.tenant),
          upgradeCode: <string>(_data.upgradeCode),
        }
      })
    }, (error) => {
      throw WebrpcRequestFailedError.new({ cause: `fetch(): ${error.message || ''}` })
    })
  }
  
  updateTenant = (args: UpdateTenantArgs, headers?: object, signal?: AbortSignal): Promise<UpdateTenantReturn> => {
    return this.fetch(
      this.url('UpdateTenant'),
      createHTTPRequest(args, headers, signal)).then((res) => {
      return buildResponse(res).then(_data => {
        return {
          tenant: <Tenant>(_data.tenant),
        }
      })
    }, (error) => {
      throw WebrpcRequestFailedError.new({ cause: `fetch(): ${error.message || ''}` })
    })
  }
  
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

export class UnauthorizedError extends WebrpcError {
  constructor(
    name: string = 'Unauthorized',
    code: number = 1000,
    message: string = 'Unauthorized access',
    status: number = 0,
    cause?: string
  ) {
    super(name, code, message, status, cause)
    Object.setPrototypeOf(this, UnauthorizedError.prototype)
  }
}

export class TenantNotFoundError extends WebrpcError {
  constructor(
    name: string = 'TenantNotFound',
    code: number = 1001,
    message: string = 'Tenant not found',
    status: number = 0,
    cause?: string
  ) {
    super(name, code, message, status, cause)
    Object.setPrototypeOf(this, TenantNotFoundError.prototype)
  }
}


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
  Unauthorized = 'Unauthorized',
  TenantNotFound = 'TenantNotFound',
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
  [1000]: UnauthorizedError,
  [1001]: TenantNotFoundError,
}

export type Fetch = (input: RequestInfo, init?: RequestInit) => Promise<Response>

