import type { Metadata } from "next";
import { Toaster } from "sonner";
import { Sidebar } from "../../components/Sidebar";
import { AdminTopBar } from "../../components/AdminTopBar";

export const metadata: Metadata = {
  title: {
    default: "Admin",
    template: "%s | Forge",
  },
};

export default function AdminLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <div className="flex min-h-screen w-full bg-background text-foreground">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <AdminTopBar />
        <main className="flex-1 overflow-x-hidden">{children}</main>
      </div>
      <Toaster theme="dark" position="top-center" richColors />
    </div>
  );
}
