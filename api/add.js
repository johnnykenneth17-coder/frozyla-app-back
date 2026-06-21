// server.js - Add this endpoint

// Get ledger stats (admin only)
app.get(
    "/api/admin/ledger/stats",
    authMiddleware,
    adminMiddleware,
    async (req, res) => {
        try {
            // Get reconciliation stats
            const { data: reconciliation, error: recError } = await supabase
                .from("ledger_reconciliation")
                .select("status, difference");

            if (recError) {
                console.error("Reconciliation stats error:", recError);
            }

            let totalEntries = 0;
            let matched = 0;
            let flagged = 0;
            let merged = 0;
            let rejected = 0;
            let totalDiscrepancy = 0;

            (reconciliation || []).forEach(entry => {
                totalEntries++;
                if (entry.status === 'matched') matched++;
                else if (entry.status === 'flagged') flagged++;
                else if (entry.status === 'merged') merged++;
                else if (entry.status === 'rejected') rejected++;
                
                if (entry.status === 'flagged') {
                    totalDiscrepancy += Math.abs(parseFloat(entry.difference || 0));
                }
            });

            // Get total volume from transactions
            const { data: volumeData, error: volError } = await supabase
                .from("wallet_transactions")
                .select("amount")
                .eq("status", "completed");

            let totalVolume = 0;
            if (!volError && volumeData) {
                (volumeData || []).forEach(tx => {
                    totalVolume += parseFloat(tx.amount || 0);
                });
            }

            res.json({
                success: true,
                stats: {
                    total_entries: totalEntries,
                    matched: matched,
                    flagged: flagged,
                    merged: merged,
                    rejected: rejected,
                    total_discrepancy: totalDiscrepancy,
                    total_volume: totalVolume,
                },
            });

        } catch (error) {
            console.error("Ledger stats error:", error);
            res.status(500).json({
                success: false,
                message: "Failed to fetch ledger stats",
                error: error.message,
            });
        }
    },
);