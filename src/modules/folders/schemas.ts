import { z } from 'zod';
import { encString, id } from '../../http/body';

export const folderBody = z.object({ name: encString.pipe(z.string().max(1000, 'Must be at most 1000 characters.')) });
export type FolderInput = z.output<typeof folderBody>;

export const idsBody = z.object({ ids: z.array(id).min(1, 'Folder ids are required') });
