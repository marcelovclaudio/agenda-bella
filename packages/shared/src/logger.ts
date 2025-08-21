/**
 * Winston-based logger configuration for Agenda Bella applications
 * @packageDocumentation
 */

import winston, { type Logger } from 'winston';

/**
 * Logger configuration options
 */
interface LoggerOptions {
  level?: string;
  service?: string;
  component?: string;
  package?: string;
}

/**
 * Create a winston logger instance with standard formatting
 */
const createLogger = (options: LoggerOptions = {}): Logger => {
  const {
    level = process.env['LOG_LEVEL'] || 'info',
    service = 'agenda-bella',
    component,
    package: packageName,
  } = options;

  const format = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.json(),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
      const logObject = {
        timestamp,
        level,
        message,
        service,
        ...(component && { component }),
        ...(packageName && { package: packageName }),
        ...meta,
      };

      return JSON.stringify(logObject);
    })
  );

  const transports: winston.transport[] = [
    new winston.transports.Console({
      format:
        process.env['NODE_ENV'] === 'development'
          ? winston.format.combine(winston.format.colorize(), winston.format.simple())
          : format,
    }),
  ];

  // Add file transport in production or when specified
  if (process.env['LOG_FILE'] || process.env['NODE_ENV'] === 'production') {
    transports.push(
      new winston.transports.File({
        filename: process.env['LOG_FILE'] || 'logs/app.log',
        format,
      })
    );
  }

  return winston.createLogger({
    level,
    format,
    transports,
    defaultMeta: {
      service,
      ...(component && { component }),
      ...(packageName && { package: packageName }),
    },
  });
};

/**
 * Default logger instance
 */
export const logger: Logger = createLogger();

/**
 * Create a child logger with additional context
 */
export const createChildLogger = (meta: Record<string, unknown>): Logger => {
  return logger.child(meta);
};

/**
 * Export winston types and runtime
 */
export type { Logger } from 'winston';
export { winston };
