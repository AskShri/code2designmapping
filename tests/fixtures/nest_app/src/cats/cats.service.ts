import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CatEntity } from './cat.entity';

@Injectable()
export class CatsService {
  constructor(@InjectRepository(CatEntity) private readonly catRepository: Repository<CatEntity>) {}

  findAll() { return this.catRepository.find(); }

  create(name: string) { return this.catRepository.save({ name }); }
}
