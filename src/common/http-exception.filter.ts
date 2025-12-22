import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
} from '@nestjs/common';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  catch(exception: any, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const res = ctx.getResponse();
    const req = ctx.getRequest();

    // ✅ 不管什麼錯誤都固定 HTTP status = 200
    res.status(200);

    // HttpException 會有 response/status，其他錯誤沒有
    const isHttp = exception instanceof HttpException;
    const status = isHttp ? exception.getStatus() : 500;

    const raw: any = isHttp ? exception.getResponse() : null;

    // 你也可以自己定義 errorCode mapping
    const code = isHttp ? status : 500;

    const message =
      typeof raw === 'string'
        ? raw
        : raw?.message || exception?.message || 'Internal Server Error';

    res.json({
      code, // 例如 400/401/500... 或自訂
      message,
      data: null,
      timestamp: Date.now(),
      path: req.originalUrl || req.url,
    });
  }
}
