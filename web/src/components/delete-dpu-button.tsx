"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { deleteDPU } from "@/lib/actions";

interface DeleteDPUButtonProps {
  id: string;
  name: string;
}

export function DeleteDPUButton({ id, name }: DeleteDPUButtonProps) {
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  const handleDelete = async () => {
    if (!confirm(`Are you sure you want to remove "${name}"?`)) {
      return;
    }

    setLoading(true);
    await deleteDPU(id);
    setLoading(false);
    router.refresh();
  };

  return (
    <Button
      variant="outline"
      size="sm"
      onClick={handleDelete}
      disabled={loading}
      className="text-red-600 hover:text-red-700 hover:bg-red-50"
    >
      {loading ? "..." : "Remove"}
    </Button>
  );
}
