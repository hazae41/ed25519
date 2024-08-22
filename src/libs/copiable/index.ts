export type BytesOrCopiable =
  | Uint8Array
  | Copiable

export interface Copiable extends Disposable {
  readonly bytes: Uint8Array
}

export class Copied {

  constructor(
    readonly bytes: Uint8Array
  ) { }

  [Symbol.dispose]() { }

}