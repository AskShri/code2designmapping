import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity('cat')
export class CatEntity {
  @PrimaryGeneratedColumn() id: number;
  @Column() name: string;
  @Column() ownerEmail: string;
}
