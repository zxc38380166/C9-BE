import { Controller, Get, Query } from '@nestjs/common';
import { CommonService } from './common.service';

@Controller('common')
export class CommonController {
  constructor(private readonly commonService: CommonService) {}

  @Get('/enums')
  async getEnums(@Query() query: string) {
    return await this.commonService.getEnums(query);
  }
}
