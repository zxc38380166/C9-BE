import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
} from '@nestjs/common';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  catch(exception: any, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const res = ctx.getResponse();
    const req = ctx.getRequest();

    const isHttp = exception instanceof HttpException;
    const status = isHttp
      ? exception.getStatus()
      : HttpStatus.INTERNAL_SERVER_ERROR;

    const raw: any = isHttp ? exception.getResponse() : null;

    const code = isHttp ? status : HttpStatus.INTERNAL_SERVER_ERROR;
    const message =
      typeof raw === 'string'
        ? raw
        : raw?.message || exception?.message || 'Internal Server Error';

    // 只有 401 回真正 HTTP 401，其它維持 200
    const httpStatus =
      status === HttpStatus.UNAUTHORIZED
        ? HttpStatus.UNAUTHORIZED
        : HttpStatus.OK;

    res.status(httpStatus).json({
      code,
      message,
      data: null,
      timestamp: Date.now(),
      path: req.originalUrl || req.url,
    });
  }
}
