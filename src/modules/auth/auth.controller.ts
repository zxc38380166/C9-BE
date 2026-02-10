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
import * as cookieParser from 'cookie-parser';
import { SendEmailVerifyDto } from './dto/send-email-verify.dto';
import type { Request } from './entities/auth-user.entity';
import { LoginGoogleDto } from './dto/login-google';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(
    @Body() body: RegisterDto,
    @Query('lang') lang: string,
    @Headers('x-app') app: string,
  ) {
    return await this.authService.register(
      body.account,
      body.password,
      body.name,
    );
  }

  @Post('login')
  async login(@Body() body: LoginDto, @Req() req) {
    return await this.authService.login(body.account, body.password, req);
  }

  @UseGuards(JwtAuthGuard)
  @Get('user-detail')
  async getUserDetail(@Query() query, @Req() req) {
    return await this.authService.getUserDetail(query, req);
  }

  @UseGuards(JwtAuthGuard)
  @Get('country-codes')
  async getCountryCodes(@Req() req) {
    return await this.authService.getCountryCodes(req);
  }

  @UseGuards(JwtAuthGuard)
  @Post('send-verify-email')
  async sendVerifyEmail(@Body() dto: SendEmailVerifyDto, @Req() req: Request) {
    return await this.authService.sendVerifyEmail(dto, req);
  }

  @UseGuards(JwtAuthGuard)
  @Post('check-verify-email')
  async checkVerifyEmail(@Body() dto, @Req() req: Request) {
    return await this.authService.checkVerifyEmail(dto, req);
  }

  @UseGuards(JwtAuthGuard)
  @Post('generate-google')
  async generateGoogle(@Req() req: Request) {
    return this.authService.generateGoogle(req);
  }

  @UseGuards(JwtAuthGuard)
  @Post('enable-google-auth')
  async enableGoogleAuth(@Body() dto, @Req() req: Request) {
    return this.authService.enableGoogleAuth(dto, req);
  }

  @UseGuards(JwtAuthGuard)
  @Post('edit-password')
  async editPassword(@Body() dto, @Req() req: Request) {
    return this.authService.editPassword(dto, req);
  }

  @Get('login-config')
  async getLoginConfig() {
    return await this.authService.getLoginConfig();
  }

  @Post('login-google')
  async loginGoogle(@Body() dto: LoginGoogleDto, @Req() req: Request) {
    return await this.authService.loginGoogle(dto, req);
  }
}
