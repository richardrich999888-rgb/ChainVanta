import ConsolePage, { type ConsolePageProps } from '../../components/console-page';

export const dynamic = 'force-dynamic';

export default function Page(props: ConsolePageProps) {
  return <ConsolePage {...props} view="Trust Graph" />;
}
