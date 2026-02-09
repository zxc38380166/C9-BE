import { IsString } from 'class-validator';

export class LoginGoogleDto {
  @IsString()
  code: string;

  @IsString()
  state: string;
}
