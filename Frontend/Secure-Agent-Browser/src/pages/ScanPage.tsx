import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Loader2, Search } from "lucide-react";

import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";

const ScanPage = () => {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setError(null);

    try {
      const res = await fetch("http://127.0.0.1:8000/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      if (!res.ok) throw new Error(await res.text());

      await res.json();

      // give Firestore a moment
      setTimeout(() => navigate("/dashboard"), 400);

    } catch (err) {
      console.error(err);
      setError("Scan failed. Backend or Selenium error.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <Navbar />

      <div className="pt-24 container mx-auto max-w-xl px-6">
        <h1 className="text-3xl font-bold mb-6 text-center">
          Scan a Web Page
        </h1>

        <form onSubmit={handleScan} className="glass flex gap-2 p-2">
          <Search className="mt-3 ml-3 text-muted-foreground" />
          <input
            className="flex-1 bg-transparent outline-none font-mono"
            placeholder="https://example.com"
            value={url}
            onChange={e => setUrl(e.target.value)}
          />
          <button className="px-5 py-2 bg-primary rounded-lg">
            {loading ? <Loader2 className="animate-spin" /> : "Scan"}
          </button>
        </form>

        {error && (
          <p className="mt-4 text-red-500 text-center">{error}</p>
        )}
      </div>

      <Footer />
    </div>
  );
};

export default ScanPage;
