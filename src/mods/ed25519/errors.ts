export type AnyError =
  | GenerateError
  | ImportError
  | ExportError
  | ConvertError
  | SignError
  | VerifyError

export class GenerateError extends Error {
  readonly #class = GenerateError
  readonly name = this.#class.name

  constructor(options?: ErrorOptions) {
    super(`Could not generate`, options)
  }

  static from(cause: unknown) {
    return new GenerateError({ cause })
  }

}

export class ImportError extends Error {
  readonly #class = ImportError
  readonly name = this.#class.name

  constructor(options?: ErrorOptions) {
    super(`Could not import`, options)
  }

  static from(cause: unknown) {
    return new ImportError({ cause })
  }

}

export class ExportError extends Error {
  readonly #class = ExportError
  readonly name = this.#class.name

  constructor(options?: ErrorOptions) {
    super(`Could not export`, options)
  }

  static from(cause: unknown) {
    return new ExportError({ cause })
  }

}

export class ConvertError extends Error {
  readonly #class = ConvertError
  readonly name = this.#class.name

  constructor(options?: ErrorOptions) {
    super(`Could not convert`, options)
  }

  static from(cause: unknown) {
    return new ConvertError({ cause })
  }

}

export class SignError extends Error {
  readonly #class = SignError
  readonly name = this.#class.name

  constructor(options?: ErrorOptions) {
    super(`Could not sign`, options)
  }

  static from(cause: unknown) {
    return new SignError({ cause })
  }

}

export class VerifyError extends Error {
  readonly #class = VerifyError
  readonly name = this.#class.name

  constructor(options?: ErrorOptions) {
    super(`Could not verify`, options)
  }

  static from(cause: unknown) {
    return new VerifyError({ cause })
  }

}