import {
  Controller,
  Post,
  Get,
  Body,
  Query,
  Headers,
  UseGuards,
  Req,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  /* 註冊 */
  @Post('register')
  async register(
    @Body() body: RegisterDto,
    @Query('lang') lang: string,
    @Headers('x-app') app: string,
  ) {
    return {
      code: 0,
      data: await this.authService.register(
        body.account,
        body.password,
        body.name,
      ),
    };
  }

  /* 登入 */
  @Post('login')
  async login(
    @Body() body: LoginDto,
    @Query('lang') lang: string,
    @Query('device') device: string,
    @Headers('x-app') app: string,
  ) {
    return {
      code: 0,
      data: await this.authService.login(body.account, body.password),
    };
  }

  /* JWT 驗證測試 */
  @UseGuards(JwtAuthGuard)
  @Get('me')
  me(@Req() req: any) {
    return {
      code: 0,
      data: {
        user: req.user,
      },
    };
  }
}
