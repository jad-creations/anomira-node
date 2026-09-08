import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { checkGeoVelocity, resetGeoState } from "../geo-velocity.js";

// Mock ip-api.com responses
const GEO_LAGOS  = { status: "success", lat: 6.5,  lon: 3.4,   country: "Nigeria", city: "Lagos"   };
const GEO_LONDON = { status: "success", lat: 51.5, lon: -0.1,  country: "UK",      city: "London"  };
const GEO_ABUJA  = { status: "success", lat: 9.1,  lon: 7.4,   country: "Nigeria", city: "Abuja"   };

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

  it("returns null on first login (no previous location)", async () => {
    fetchSpy.mockResolvedValue({ ok: true, json: async () => GEO_LAGOS });
    const result = await checkGeoVelocity("user1", "102.89.23.1", Date.now());
    expect(result).toBeNull();
  });

  it("returns null for same IP on consecutive logins", async () => {
    fetchSpy.mockResolvedValue({ ok: true, json: async () => GEO_LAGOS });
    const now = Date.now();
    await checkGeoVelocity("user2", "102.89.23.1", now);
    const result = await checkGeoVelocity("user2", "102.89.23.1", now + 60_000);
    expect(result).toBeNull();
  });

  it("returns null for nearby cities (no impossible travel)", async () => {
    fetchSpy
      .mockResolvedValueOnce({ ok: true, json: async () => GEO_LAGOS })   // login 1
      .mockResolvedValueOnce({ ok: true, json: async () => GEO_ABUJA });  // login 2

    const now = Date.now();
    await checkGeoVelocity("user3", "102.89.23.1", now);
    const result = await checkGeoVelocity("user3", "77.88.55.1", now + 3_600_000); // 1h later
    expect(result).toBeNull(); // Lagos→Abuja ~490km in 1h = 490km/h < 900km/h
  });

  it("detects impossible travel (Lagos → London in 3 minutes)", async () => {
    fetchSpy
      .mockResolvedValueOnce({ ok: true, json: async () => GEO_LAGOS })
      .mockResolvedValueOnce({ ok: true, json: async () => GEO_LONDON });

    const now = Date.now();
    await checkGeoVelocity("user4", "102.89.23.1", now);

    const result = await checkGeoVelocity("user4", "81.2.45.1", now + 3 * 60_000); // 3 minutes later
    expect(result).not.toBeNull();
    expect(result?.isImpossible).toBe(true);
    expect(result?.distanceKm).toBeGreaterThan(5000);
    expect(result?.speedKmH).toBeGreaterThan(900);
    expect(result?.from.city).toBe("Lagos");
    expect(result?.to.city).toBe("London");
  });

  it("returns null for private/loopback IPs", async () => {
    const result = await checkGeoVelocity("user5", "192.168.1.1", Date.now());
    expect(result).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("returns null when geo lookup fails (silent)", async () => {
    fetchSpy.mockRejectedValue(new Error("Network error"));
    const result = await checkGeoVelocity("user6", "102.89.23.1", Date.now());
    expect(result).toBeNull();
  });

  it("tracks different users independently", async () => {
    fetchSpy
      .mockResolvedValueOnce({ ok: true, json: async () => GEO_LAGOS })   // userA first login
      .mockResolvedValueOnce({ ok: true, json: async () => GEO_LAGOS })   // userB first login
      .mockResolvedValueOnce({ ok: true, json: async () => GEO_LONDON });  // userA second login

    const now = Date.now();
    await checkGeoVelocity("userA", "102.89.23.1", now);
    await checkGeoVelocity("userB", "102.89.23.2", now);

    // userA: Lagos → London in 3 min = impossible
    const result = await checkGeoVelocity("userA", "81.2.45.1", now + 3 * 60_000);
    expect(result?.isImpossible).toBe(true);
  });
});
