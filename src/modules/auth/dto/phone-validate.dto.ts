import { IsOptional, IsString, Length } from 'class-validator';

export class PhoneValidateDto {
  @IsString()
  @Length(3, 40)
  phone!: string;

  // ISO 3166-1 alpha-2，例如 "TW" / "US"
  @IsOptional()
  @IsString()
  @Length(2, 2)
  country?: string;
}
