export type ApiResponse<T = any> = {
  code: number; // 0=成功
  message: string; // 'ok'
  result: T;
  timestamp: number;
  path: string;
};

import {
  CallHandler,
  ExecutionContext,
  HttpStatus,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { Observable, map } from 'rxjs';

@Injectable()
export class SuccessResponseInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const http = context.switchToHttp();
    const req = http.getRequest();

    return next.handle().pipe(
      map((data) => {
        // ✅ 如果你某些 API 已經自己回傳固定格式，避免重複包一層
        if (
          data &&
          typeof data === 'object' &&
          'code' in data &&
          'message' in data &&
          'data' in data
        ) {
          return data;
        }

        const resBody: ApiResponse = {
          code: HttpStatus.OK,
          message: 'ok',
          result: data ?? null,
          timestamp: Date.now(),
          path: req.originalUrl || req.url,
        };

        return resBody;
      }),
    );
  }
}
