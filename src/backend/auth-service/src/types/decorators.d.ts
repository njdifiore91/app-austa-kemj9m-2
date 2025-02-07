import { RequestHandler } from 'express';
import { RateLimitRequestHandler } from 'express-rate-limit';

declare global {
  // Class decorators
  function controller(path: string): ClassDecorator;
  function hipaaCompliant(): ClassDecorator;
  function securityAudit(): ClassDecorator;

  // Method decorators
  function post(path: string): MethodDecorator;
  function hipaaValidate(): MethodDecorator;
  function auditLog(): MethodDecorator;
  function rateLimit(options: RateLimitRequestHandler): MethodDecorator;

  // Type declarations for custom decorators
  interface ClassDecorator {
    (target: Function): void;
  }

  interface MethodDecorator {
    (target: Object, propertyKey: string | symbol, descriptor: PropertyDescriptor): PropertyDescriptor | void;
  }

  interface PropertyDecorator {
    (target: Object, propertyKey: string | symbol): void;
  }

  interface ParameterDecorator {
    (target: Object, propertyKey: string | symbol, parameterIndex: number): void;
  }
} 