import { describe, expect, it } from 'vitest';
import { POPOVER_MAX_WIDTH, placePopover } from '../ui/Select';

const vp = { width: 1600, height: 1000 };
const trigger = (left: number, width: number, top = 300, h = 32) => ({ left, right: left + width, top, bottom: top + h, width });

describe('Select popover placement', () => {
  it('is never narrower than its trigger', () => {
    const p = placePopover(trigger(500, 140), vp, { width: 90 });
    expect(p.width).toBe(140);
    expect(p.left).toBe(500);
    expect(p.top).toBe(336);
    expect(p.bottom).toBeUndefined();
  });

  it('grows to fit the longest option without wrapping, up to the max', () => {
    expect(placePopover(trigger(500, 120), vp, { width: 233.2 }).width).toBe(234);
    expect(placePopover(trigger(500, 120), vp, { width: 900 }).width).toBe(POPOVER_MAX_WIDTH);
    // a trigger wider than the max still wins (full-width form fields)
    expect(placePopover(trigger(100, 600), vp, { width: 300 }).width).toBe(600);
  });

  it('right-aligns with the trigger when it would overflow the viewport, then clamps', () => {
    const p = placePopover(trigger(1450, 130), vp, { width: 300 });
    expect(p.width).toBe(300);
    expect(p.left).toBe(1580 - 300); // right edges aligned
    const q = placePopover(trigger(1500, 60), { width: 1600, height: 1000 }, { width: 400 });
    expect(q.left + q.width).toBeLessThanOrEqual(1592);
  });

  it('never exceeds the viewport on narrow screens', () => {
    const p = placePopover(trigger(16, 340), { width: 360, height: 700 }, { width: 600 });
    expect(p.width).toBe(344);
    expect(p.left).toBe(8);
  });

  it('flips above the trigger when there is clearly more room there', () => {
    const p = placePopover(trigger(200, 160, 900), vp, { width: 100 });
    expect(p.top).toBeUndefined();
    expect(p.bottom).toBe(1000 - 900 + 4);
    expect(p.maxHeight).toBeLessThanOrEqual(320);
    const below = placePopover(trigger(200, 160, 100), vp, { width: 100 }, { searchable: true });
    expect(below.top).toBe(136);
    expect(below.maxHeight).toBe(360);
  });
});
