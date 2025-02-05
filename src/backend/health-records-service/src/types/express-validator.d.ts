import { ValidationError } from "express-validator"

declare module "express-validator" {
  interface ValidationResult {
    isEmpty(): boolean
    array(): ValidationError[]
  }

  interface ValidationChain {
    isString(): ValidationChain
    notEmpty(): ValidationChain
    isIn(values: any[]): ValidationChain
    isArray(): ValidationChain
    optional(): ValidationChain
  }
}
