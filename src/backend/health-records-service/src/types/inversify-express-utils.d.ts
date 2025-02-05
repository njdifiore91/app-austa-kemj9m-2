declare module "inversify-express-utils" {
  export function controller(path: string): ClassDecorator
  export function httpGet(path: string): MethodDecorator
  export function httpPost(path: string): MethodDecorator
  export function httpPut(path: string): MethodDecorator
  export function httpDelete(path: string): MethodDecorator
}
