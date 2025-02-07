declare module 'opossum' {
  export class CircuitBreaker<T = any> {
    constructor(
      action: (...args: any[]) => Promise<T>,
      options?: {
        timeout?: number;
        resetTimeout?: number;
        errorThresholdPercentage?: number;
        rollingCountTimeout?: number;
        rollingCountBuckets?: number;
        name?: string;
        group?: string;
        enabled?: boolean;
        allowWarmUp?: boolean;
        volumeThreshold?: number;
        errorFilter?: (err: Error) => boolean;
      }
    );

    fire(...args: any[]): Promise<T>;
    fallback(fn: (...args: any[]) => Promise<T> | T): this;
    open(): void;
    close(): void;
    disable(): void;
    enable(): void;
    isOpen(): boolean;
    isClosed(): boolean;
    isHalfOpen(): boolean;
  }
} 