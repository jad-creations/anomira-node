import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { checkGeoVelocity, resetGeoState } from "../geo-velocity.js";

const GEO_URL = "https://ingest.example.com/v1/geo";

const GEO_LAGOS  = { lat: 6.5,  lon: 3.4,   country: "Nigeria", city: "Lagos"   };
const GEO_LONDON = { lat: 51.5, lon: -0.1,  country: "UK",      city: "London"  };
const GEO_ABUJA  = { lat: 9.1,  lon: 7.4,   country: "Nigeria", city: "Abuja"   };
const GEO_LAGOS_LNG = { lat: 6.5, lng: 3.4, country: "Nigeria", city: "Lagos" };

describe("checkGeoVelocity", () => {
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    resetGeoState();
    fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("returns null when lookupUrl is omitted", async () => {
    const result = await checkGeoVelocity("user1", "102.89.23.1", Date.now());
    expect(result).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("returns null on first login (no previous location)", async () => {
    fetchSpy.mockResolvedValue({ ok: true, json: async () => GEO_LAGOS });
    const result = await checkGeoVelocity("user1", "102.89.23.1", Date.now(), GEO_URL);
    expect(result).toBeNull();
  });

  it("accepts lng as well as lon", async () => {
    fetchSpy.mockResolvedValue({ ok: true, json: async () => GEO_LAGOS_LNG });
    const result = await checkGeoVelocity("user_lng", "102.89.23.1", Date.now(), GEO_URL);
    expect(result).toBeNull();
    expect(fetchSpy).toHaveBeenCalledOnce();
  });

  it("returns null for same IP on consecutive logins", async () => {
    fetchSpy.mockResolvedValue({ ok: true, json: async () => GEO_LAGOS });
    const now = Date.now();
    await checkGeoVelocity("user2", "102.89.23.1", now, GEO_URL);
    const result = await checkGeoVelocity("user2", "102.89.23.1", now + 60_000, GEO_URL);
    expect(result).toBeNull();
  });

  it("returns null for nearby cities (no impossible travel)", async () => {
    fetchSpy
      .mockResolvedValueOnce({ ok: true, json: async () => GEO_LAGOS })
      .mockResolvedValueOnce({ ok: true, json: async () => GEO_ABUJA });

    const now = Date.now();
    await checkGeoVelocity("user3", "102.89.23.1", now, GEO_URL);
    const result = await checkGeoVelocity("user3", "77.88.55.1", now + 3_600_000, GEO_URL);
    expect(result).toBeNull();
  });

  it("detects impossible travel (Lagos → London in 3 minutes)", async () => {
    fetchSpy
      .mockResolvedValueOnce({ ok: true, json: async () => GEO_LAGOS })
      .mockResolvedValueOnce({ ok: true, json: async () => GEO_LONDON });

    const now = Date.now();
    await checkGeoVelocity("user4", "102.89.23.1", now, GEO_URL);

    const result = await checkGeoVelocity("user4", "81.2.45.1", now + 3 * 60_000, GEO_URL);
    expect(result).not.toBeNull();
    expect(result?.isImpossible).toBe(true);
    expect(result?.distanceKm).toBeGreaterThan(5000);
    expect(result?.speedKmH).toBeGreaterThan(900);
    expect(result?.from.city).toBe("Lagos");
    expect(result?.to.city).toBe("London");
  });

  it("returns null for private/loopback IPs", async () => {
    const result = await checkGeoVelocity("user5", "192.168.1.1", Date.now(), GEO_URL);
    expect(result).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("returns null when geo lookup fails (silent)", async () => {
    fetchSpy.mockRejectedValue(new Error("Network error"));
    const result = await checkGeoVelocity("user6", "102.89.23.1", Date.now(), GEO_URL);
    expect(result).toBeNull();
  });

  it("tracks different users independently", async () => {
    fetchSpy
      .mockResolvedValueOnce({ ok: true, json: async () => GEO_LAGOS })
      .mockResolvedValueOnce({ ok: true, json: async () => GEO_LAGOS })
      .mockResolvedValueOnce({ ok: true, json: async () => GEO_LONDON });

    const now = Date.now();
    // Distinct IPs so geo-cache does not collapse the lookups
    await checkGeoVelocity("userA", "102.89.23.1", now, GEO_URL);
    await checkGeoVelocity("userB", "102.89.23.2", now, GEO_URL);
    const result = await checkGeoVelocity("userA", "81.2.45.1", now + 3 * 60_000, GEO_URL);
    expect(result).not.toBeNull();
    expect(result?.isImpossible).toBe(true);
  });
});
