import { IsEmail, IsOptional, IsString } from 'class-validator';

export class SendEmailVerifyDto {
  @IsEmail()
  email: string;

  @IsOptional()
  @IsString()
  subject?: string;
}
