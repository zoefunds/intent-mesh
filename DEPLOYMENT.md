# Deployment checklist

This repository deliberately does not claim a deployment that has not occurred.

1. Install the recorded stable toolchain and run `python scripts/record_toolchain.py`.
2. Run `python scripts/verify_network.py`; stop if it does not print chain `61999`.
3. Run lint and direct tests.
4. Deploy with the current official GenLayer CLI or `gltest` Studionet flow.
5. Save the finalized contract address, deployment transaction hash, and lifecycle transaction hashes in `artifacts/studionet-deployment.json`.
6. Exercise publish → request → resolve → read using real validator-backed consensus.
7. Re-run the network check before every funded write.
8. Push the exact source and artifacts to the supplied GitHub repository.

Never substitute 61997, Bradbury, localnet, or a simulated receipt for the final evidence.
