# Demo video review

Source of `docs/assets/sdn-guardian-demo.gif` (README, 960 px, 12 fps, 5.7 MB) and
`docs/assets/sdn-guardian-demo.mp4` (1920x1080, 30 fps, 4.0 MB, for LinkedIn). 20.2 s, silent.

## Creative calls

- One stage, six scenes: title → Observe (SYN flood counter) → Orient (VLAN 20 ≠ 99) → Decide
  (prio 100 FAIL SHADOWED, fix 101, PASS) → Act (30 s dead-man's switch, confirm, COMMITTED) →
  closing line with the repo URL. An OODA stepper runs across the four middle scenes.
- Cisco-like palette (blue #049FD9, navy #0D274D, green #6CC04A, red #E2231A, amber #FBAB18),
  Inter + JetBrains Mono. No Cisco logo or trademarked artwork.
- Values match Colab run 4 (priority 101, 30 s timeout, IDs abbreviated). Tool-call lines are
  shortened (`simulate_flow_impact(priority=100)`), not full argument lists.
- Silent on purpose: a GIF has no audio. `film_silent` is the only remaining check warning.

## What was checked

- `hyperframes check`: no errors; warnings fixed except `film_silent`.
- Looked at the review beat sheet and the PASS (12.6 s), COMMITTED (16.6 s) and closing
  (19.5 s) frames, plus one frame of the compressed GIF.
- Not checked: the phone-width sheet in detail; the tool-call lines are small on a phone.

## Weakest shot / next changes

- Content sits slightly high in the frame (empty band at the bottom). Moving cards down ~40 px
  would balance it.
- Scenes change with the same blur swap; a match cut from the PASS stamp into the Act card
  would read as more intentional.

## Re-render

```bash
cd docs/demo-video
npx hyperframes render --format gif --fps 15 --output /tmp/full.gif
ffmpeg -i /tmp/full.gif -vf "fps=12,scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=96:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle" -loop 0 ../assets/sdn-guardian-demo.gif
npx hyperframes render --quality delivery --output ../assets/sdn-guardian-demo.mp4
```
