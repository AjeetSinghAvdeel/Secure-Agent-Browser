export type DateLike =
  | Date
  | string
  | number
  | {
      toDate?: () => Date;
      toMillis?: () => number;
    }
  | null
  | undefined;

export const toDateValue = (value: DateLike): Date | null => {
  if (!value) return null;
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  if (typeof value === "object" && typeof value.toDate === "function") {
    const converted = value.toDate();
    return Number.isNaN(converted.getTime()) ? null : converted;
  }
  if (typeof value === "object" && typeof value.toMillis === "function") {
    const converted = new Date(value.toMillis());
    return Number.isNaN(converted.getTime()) ? null : converted;
  }
  const converted = new Date(value);
  return Number.isNaN(converted.getTime()) ? null : converted;
};
