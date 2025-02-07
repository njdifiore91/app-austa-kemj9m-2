import { Request, Response, NextFunction } from 'express';
import { RateLimitRequestHandler } from 'express-rate-limit';
import 'reflect-metadata';

/**
 * Route controller decorator
 */
export function controller(path: string): ClassDecorator {
  return function (target: Function) {
    Reflect.defineMetadata('path', path, target);
  };
}

/**
 * HIPAA compliance decorator
 */
export function hipaaCompliant(): ClassDecorator {
  return function (target: Function) {
    Reflect.defineMetadata('hipaaCompliant', true, target);
  };
}

/**
 * Security audit decorator
 */
export function securityAudit(): ClassDecorator {
  return function (target: Function) {
    Reflect.defineMetadata('securityAudit', true, target);
  };
}

/**
 * HTTP POST method decorator
 */
export function post(path: string): MethodDecorator {
  return function (target: Object, propertyKey: string | symbol, descriptor: PropertyDescriptor) {
    Reflect.defineMetadata('path', path, target, propertyKey);
    Reflect.defineMetadata('method', 'post', target, propertyKey);
  };
}

/**
 * HIPAA validation decorator
 */
export function hipaaValidate(): MethodDecorator {
  return function (target: Object, propertyKey: string | symbol, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      // Add HIPAA validation logic here
      return await originalMethod.apply(this, args);
    };

    return descriptor;
  };
}

/**
 * Audit logging decorator
 */
export function auditLog(): MethodDecorator {
  return function (target: Object, propertyKey: string | symbol, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      // Add audit logging logic here
      return await originalMethod.apply(this, args);
    };

    return descriptor;
  };
}

/**
 * Rate limiting decorator
 */
export function rateLimit(handler: RateLimitRequestHandler): MethodDecorator {
  return function (target: Object, propertyKey: string | symbol, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (req: Request, res: Response, next: NextFunction) {
      await new Promise((resolve) => handler(req, res, resolve as NextFunction));
      return await originalMethod.apply(this, [req, res, next]);
    };

    return descriptor;
  };
} 