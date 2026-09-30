// Bitwarden's envelope for lists.
export const listJson = <T>(data: T[], continuationToken: string | null = null) => ({ data, object: 'list', continuationToken });
