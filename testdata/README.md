# Test data

- `contract.json` - the names the broker and Straiker's relay must derive identically (agent id, relay login,
  socket directory and paths). Generated from the relay's reference implementation; the relay's tests
  (`straiker-ai/platform`, `services/broker/relay`) check the same file, so a change here must land on both sides.
