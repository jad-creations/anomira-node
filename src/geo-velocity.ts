/**
 * Geo-velocity detector
 * ─────────────────────
 * Tracks the last known IP location per userId.
 * On each successful login, checks if the new login would require
 * physically impossible travel from the previous login location.
 *
 * Geo-lookup is delegated to the Anomira ingest service (server-side MaxMind)
 * via the configurable `geoLookupUrl`. Falls back gracefully if unreachable.
 *
 * Threshold: 900 km/h (commercial jet cruising speed).
 */

export interface GeoPoint {
  lat:      number;
  lng:      number;
  ip:       string;
  tsMs:     number;
  city?:    string;
  country?: string;
}

export interface GeoVelocityResult {
  isImpossible: boolean;
  distanceKm:   number;
  speedKmH:     number;
  from:         GeoPoint;
  to:           GeoPoint;
}

// In-memory last-login state per userId
const lastSeen = new Map<string, GeoPoint>();

// Geo-lookup response cache: IP → GeoPoint (1h TTL)
const geoCache = new Map<string, { point: Omit<GeoPoint, "tsMs">; expiresAt: number }>();

const MAX_SPEED_KMH = 900;

const PRIVATE_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^::1$/,
  /^0\.0\.0\.0$/,
  /^fc00:/i,
  /^fe80:/i,
];

function isPrivateIp(ip: string): boolean {
  return PRIVATE_RANGES.some((r) => r.test(ip));
}

/**
 * Lookup geo coordinates for an IP via the Anomira geo endpoint.
 * The ingest service uses MaxMind (no rate limits).
 * Returns null for private/loopback IPs or on any network failure.
 */
async function lookupGeo(
  ip:         string,
  lookupUrl?: string,
): Promise<Omit<GeoPoint, "tsMs"> | null> {
  if (!ip || isPrivateIp(ip)) return null;

  const cached = geoCache.get(ip);
  if (cached && cached.expiresAt > Date.now()) return cached.point;

  // Use the Anomira geo endpoint (MaxMind-backed, no rate limits)
  // Falls back to null on any failure — never crashes the SDK
  const url = lookupUrl ? `${lookupUrl}?ip=${encodeURIComponent(ip)}` : null;
  if (!url) return null;

  try {
    const res  = await fetch(url, { signal: AbortSignal.timeout(2_000) });
    if (!res.ok) return null;

    const data = await res.json() as {
      lat?: number; lng?: number; country?: string; city?: string;
    };

    if (data.lat == null || data.lng == null) return null;

    const point: Omit<GeoPoint, "tsMs"> = {
      ip,
      lat:     data.lat,
      lng:     data.lng,
      country: data.country,
      city:    data.city,
    };

    geoCache.set(ip, { point, expiresAt: Date.now() + 3_600_000 });
    return point;
  } catch {
    return null;
  }
}

/** Haversine formula — great-circle distance in km */
function haversineKm(lat1: number, lng1: number, lat2: number, lng2: number): number {
  const R    = 6371;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function toRad(deg: number): number { return (deg * Math.PI) / 180; }

/**
 * Check for impossible travel on a successful login event.
 *
 * @param userId    - The authenticated user's ID
 * @param ip        - The IP from which they just logged in
 * @param tsMs      - Timestamp of this login (ms since epoch)
 * @param lookupUrl - Base URL for geo lookup endpoint (optional)
 */
export async function checkGeoVelocity(
  userId:     string,
  ip:         string,
  tsMs:       number,
  lookupUrl?: string,
): Promise<GeoVelocityResult | null> {
  const geo = await lookupGeo(ip, lookupUrl);
  if (!geo) return null;

  const currentPoint: GeoPoint = { ...geo, tsMs };
  const prev = lastSeen.get(userId);

  lastSeen.set(userId, currentPoint);

  // Evict entries older than 24 hours
  if (lastSeen.size > 10_000) {
    const cutoff = Date.now() - 86_400_000;
    for (const [key, val] of lastSeen) {
      if (val.tsMs < cutoff) lastSeen.delete(key);
    }
  }

  if (!prev) return null;
  if (prev.ip === ip) return null;

  const distanceKm = haversineKm(prev.lat, prev.lng, currentPoint.lat, currentPoint.lng);
  const hours      = Math.max((tsMs - prev.tsMs) / 3_600_000, 0.001);
  const speedKmH   = distanceKm / hours;

  if (speedKmH < MAX_SPEED_KMH) return null;

  return {
    isImpossible: true,
    distanceKm:   Math.round(distanceKm),
    speedKmH:     Math.round(speedKmH),
    from:         prev,
    to:           currentPoint,
  };
}

export function resetGeoState(): void {
  lastSeen.clear();
  geoCache.clear();
}
