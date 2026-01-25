import { Injectable } from '@nestjs/common';
import { ENUMS } from 'src/enum';

@Injectable()
export class CommonService {
  async getEnums(query) {
    return ENUMS;
  }
}
