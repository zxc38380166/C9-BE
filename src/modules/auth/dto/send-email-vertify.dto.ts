import { IsEmail, IsOptional, IsString } from 'class-validator';

export class SendTestDto {
  @IsEmail()
  email: string;

  @IsOptional()
  @IsString()
  subject?: string;
}
