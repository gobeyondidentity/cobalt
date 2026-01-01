"use client"

import * as React from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Badge } from "@/components/ui/badge"
import { HelpTooltip } from "@/components/help-tooltip"
import { X } from "lucide-react"
import type { Tenant } from "@/lib/mock-data"

interface CreateTenantModalProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  tenant?: Tenant | null
  onSave?: (data: Partial<Tenant>) => void
}

export function CreateTenantModal({ open, onOpenChange, tenant, onSave }: CreateTenantModalProps) {
  const [name, setName] = React.useState(tenant?.name || "")
  const [description, setDescription] = React.useState(tenant?.description || "")
  const [contactEmail, setContactEmail] = React.useState(tenant?.contactEmail || "")
  const [tagInput, setTagInput] = React.useState("")
  const [tags, setTags] = React.useState<string[]>(tenant?.tags || [])

  React.useEffect(() => {
    if (tenant) {
      setName(tenant.name)
      setDescription(tenant.description)
      setContactEmail(tenant.contactEmail)
      setTags(tenant.tags)
    } else {
      setName("")
      setDescription("")
      setContactEmail("")
      setTags([])
    }
  }, [tenant, open])

  const handleAddTag = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault()
      const newTag = tagInput.trim()
      if (newTag && !tags.includes(newTag)) {
        setTags([...tags, newTag])
      }
      setTagInput("")
    }
  }

  const handleRemoveTag = (tagToRemove: string) => {
    setTags(tags.filter((tag) => tag !== tagToRemove))
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSave?.({
      name,
      description,
      contactEmail,
      tags,
    })
    onOpenChange(false)
  }

  const isEditing = !!tenant

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[480px]">
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>
              {isEditing ? "Edit " : "Create "}
              <HelpTooltip term="tenant">Tenant</HelpTooltip>
            </DialogTitle>
            <DialogDescription>
              {isEditing
                ? "Update the tenant information below."
                : "Create a new tenant to organize your DPUs by customer or environment."}
            </DialogDescription>
          </DialogHeader>

          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="name">
                Name <span className="text-destructive">*</span>
              </Label>
              <Input
                id="name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g., Production, Development"
                required
              />
            </div>

            <div className="grid gap-2">
              <Label htmlFor="description">Description</Label>
              <Textarea
                id="description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Brief description of this tenant's purpose"
                rows={3}
              />
            </div>

            <div className="grid gap-2">
              <Label htmlFor="email">Contact Email</Label>
              <Input
                id="email"
                type="email"
                value={contactEmail}
                onChange={(e) => setContactEmail(e.target.value)}
                placeholder="contact@example.com"
              />
            </div>

            <div className="grid gap-2">
              <Label htmlFor="tags">
                <HelpTooltip term="tags">Tags</HelpTooltip>
              </Label>
              <Input
                id="tags"
                value={tagInput}
                onChange={(e) => setTagInput(e.target.value)}
                onKeyDown={handleAddTag}
                placeholder="Type and press Enter to add tags"
              />
              {tags.length > 0 && (
                <div className="flex flex-wrap gap-2 mt-2">
                  {tags.map((tag) => (
                    <Badge key={tag} variant="secondary" className="gap-1 pr-1">
                      {tag}
                      <button
                        type="button"
                        onClick={() => handleRemoveTag(tag)}
                        className="ml-1 rounded-full hover:bg-muted p-0.5"
                      >
                        <X className="h-3 w-3" />
                      </button>
                    </Badge>
                  ))}
                </div>
              )}
            </div>
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" className="bg-pine-green hover:bg-pine-green/90 text-white">
              {isEditing ? "Save Changes" : "Create Tenant"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
