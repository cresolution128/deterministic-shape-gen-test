# Step-2 Demo — Deterministic Shape Generator

This package contains the Step-2 demo (HTML + JS) along with sample exports requested for review.

## Contents
- `index.html` — Main demo interface.
- `script.js` — Shape generation and test logic.
- `exports/`
  - `sample1.svg`
  - `sample1.png`
  - `sample1.json`
  - `sample2.svg`
  - `sample2.png`
  - `sample2.json`

## Demo Link
You can also test the live demo here:  
[https://deterministic-shape-gen-test.vercel.app/](https://deterministic-shape-gen-test.vercel.app/)

## How to Run
1. Open `index.html` in a browser.
2. Use the buttons:
   - **Run T1** → Generates deterministic shape for Control Vector 1.
   - **Run T2** → Generates deterministic shape for Control Vector 2.
3. Each run shows that:
   - The output is **deterministic** (same vector = same shape).
   - The output is **unique** (different vectors = different shapes).

## Exports
Inside the `exports/` folder you will find:
- **SVG**: Vector format of the generated shape.
- **PNG**: Raster image snapshot.
- **JSON**: Raw data used to generate the shape.

## Notes
- The current shape does not yet match the exact reference design, but it passes the two key tests (determinism and uniqueness).
- Next steps will focus on refining the visual output according to the reference.

---

Prepared by Milos
