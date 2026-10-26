import Link from "next/link";

export default function Home() {
  return (
    <main className="flex min-h-dvh items-center justify-center">
      <Link href="/register">Registrieren</Link>
    </main>
  );
}
