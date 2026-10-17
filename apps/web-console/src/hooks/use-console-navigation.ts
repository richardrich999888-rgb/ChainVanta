'use client';
import { useRouter } from 'next/navigation';
import { viewUrl, type View } from '../lib/navigation';

export function useConsoleNavigation() {
  const router = useRouter();
  return (view: View, assessmentId?: string) => router.push(viewUrl(view, assessmentId));
}
