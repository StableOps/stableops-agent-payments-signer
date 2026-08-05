export class AgentSignerError extends Error {
  constructor(
    message: string,
    readonly code: string,
    readonly statusCode = 400,
  ) {
    super(message)
    this.name = 'AgentSignerError'
  }
}

export class InvalidGrantError extends AgentSignerError {
  constructor(message: string) {
    super(message, 'invalid_grant', 401)
    this.name = 'InvalidGrantError'
  }
}

export class GrantBindingError extends AgentSignerError {
  constructor(message: string) {
    super(message, 'grant_binding_mismatch', 403)
    this.name = 'GrantBindingError'
  }
}

export class GrantReplayConflictError extends AgentSignerError {
  constructor() {
    super('grant ID was already used with different signed claims', 'grant_replay_conflict', 409)
    this.name = 'GrantReplayConflictError'
  }
}
