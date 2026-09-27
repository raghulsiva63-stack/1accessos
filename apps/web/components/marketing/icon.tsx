import {
  Activity, BadgeCheck, Braces, BriefcaseBusiness, Building2, Code2, CreditCard, Database, EyeOff, FileClock,
  FileKey, Fingerprint, FolderLock, Gauge, Heart, History, IdCard, KeyRound, Laptop, LayoutDashboard, Link2,
  LockKeyhole, Paperclip, Repeat2, Search, Send, Server, Share2, ShieldCheck, SlidersHorizontal, Smartphone,
  Sparkles, Star, TimerOff, UserRound, UserX, Users, WandSparkles, Waypoints, Zap,
} from "lucide-react";
import type { IconName } from "@/lib/marketing/catalog";

const ICONS: Record<IconName, typeof KeyRound> = {
  Activity, BadgeCheck, Braces, BriefcaseBusiness, Building2, Code2, CreditCard, Database, EyeOff, FileClock,
  FileKey, Fingerprint, FolderLock, Gauge, Heart, History, IdCard, KeyRound, Laptop, LayoutDashboard, Link2,
  LockKeyhole, Paperclip, Repeat2, Search, Send, Server, Share2, ShieldCheck, SlidersHorizontal, Smartphone,
  Sparkles, Star, TimerOff, UserRound, UserX, Users, WandSparkles, Waypoints, Zap,
};

export function MarketingIcon({ name }: { name: IconName }) {
  const Icon = ICONS[name];
  return <Icon aria-hidden />;
}
