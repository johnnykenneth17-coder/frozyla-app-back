// ============================================
// PAYMENT & WALLET SYSTEM ROUTES
// ============================================

// ===== HELPER FUNCTIONS =====

function generateReference() {
    const prefix = 'FZ';
    const timestamp = Date.now().toString(36).toUpperCase();
    const random = Math.random().toString(36).substring(2, 8).toUpperCase();
    return `${prefix}${timestamp}${random}`;
}

function generateAccountNumber() {
    const prefix = 'FZ';
    const number = Math.floor(1000000000 + Math.random() * 9000000000);
    return `${prefix}${number}`;
}

async function updateUserBalance(userId, amount, transactionType, description, category, reference, orderId = null, fundingRequestId = null) {
    // Start a transaction
    const { data: user, error: userError } = await supabase
        .from('users')
        .select('balance')
        .eq('id', userId)
        .single();

    if (userError || !user) {
        throw new Error('User not found');
    }

    const balanceBefore = parseFloat(user.balance);
    const amountNum = parseFloat(amount);
    let balanceAfter;

    if (transactionType === 'credit') {
        balanceAfter = balanceBefore + amountNum;
    } else if (transactionType === 'debit') {
        if (balanceBefore < amountNum) {
            throw new Error('Insufficient balance');
        }
        balanceAfter = balanceBefore - amountNum;
    } else {
        throw new Error('Invalid transaction type');
    }

    // Update user balance
    const { error: updateError } = await supabase
        .from('users')
        .update({ 
            balance: balanceAfter,
            updated_at: new Date().toISOString()
        })
        .eq('id', userId);

    if (updateError) throw updateError;

    // Create transaction record
    const transactionId = uuidv4();
    const { error: txError } = await supabase
        .from('wallet_transactions')
        .insert([{
            id: transactionId,
            user_id: userId,
            transaction_type: transactionType,
            amount: amountNum,
            balance_before: balanceBefore,
            balance_after: balanceAfter,
            reference: reference,
            description: description,
            category: category,
            order_id: orderId,
            funding_request_id: fundingRequestId,
            status: 'completed',
            created_at: new Date().toISOString(),
            completed_at: new Date().toISOString()
        }]);

    if (txError) throw txError;

    // Update account ledger
    await updateAccountLedger(userId);

    return { balanceBefore, balanceAfter, transactionId };
}

async function updateAccountLedger(userId) {
    const { data: user, error: userError } = await supabase
        .from('users')
        .select('balance')
        .eq('id', userId)
        .single();

    if (userError || !user) return;

    const actualBalance = parseFloat(user.balance);

    // Get latest ledger entry
    const { data: latestLedger, error: ledgerError } = await supabase
        .from('account_ledger')
        .select('ledger_balance')
        .eq('user_id', userId)
        .order('created_at', { ascending: false })
        .limit(1);

    let ledgerBalance = actualBalance;

    if (!ledgerError && latestLedger && latestLedger.length > 0) {
        ledgerBalance = parseFloat(latestLedger[0].ledger_balance);
    }

    const difference = actualBalance - ledgerBalance;
    const status = Math.abs(difference) < 0.01 ? 'matched' : 'flagged';

    const { error: insertError } = await supabase
        .from('account_ledger')
        .insert([{
            user_id: userId,
            ledger_balance: ledgerBalance,
            actual_balance: actualBalance,
            status: status,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
        }]);

    if (insertError) {
        console.error('Failed to update ledger:', insertError);
    }
}

// ===== USER ROUTES =====

// Get user wallet balance
app.get('/api/wallet/balance', authMiddleware, async (req, res) => {
    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('balance, account_number, account_status')
            .eq('id', req.userId)
            .single();

        if (error || !user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            balance: parseFloat(user.balance),
            account_number: user.account_number,
            account_status: user.account_status
        });
    } catch (error) {
        console.error('Wallet balance error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch balance'
        });
    }
});

// Get user transactions
app.get('/api/wallet/transactions', authMiddleware, async (req, res) => {
    try {
        const { limit = 50, offset = 0, type, start_date, end_date } = req.query;

        let query = supabase
            .from('wallet_transactions')
            .select('*')
            .eq('user_id', req.userId)
            .order('created_at', { ascending: false })
            .range(parseInt(offset), parseInt(offset) + parseInt(limit) - 1);

        if (type) {
            query = query.eq('transaction_type', type);
        }

        if (start_date) {
            query = query.gte('created_at', start_date);
        }

        if (end_date) {
            query = query.lte('created_at', end_date);
        }

        const { data: transactions, error } = await query;

        if (error) throw error;

        // Get total count
        const { count, error: countError } = await supabase
            .from('wallet_transactions')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', req.userId);

        res.json({
            success: true,
            transactions: transactions || [],
            total: count || 0,
            limit: parseInt(limit),
            offset: parseInt(offset)
        });
    } catch (error) {
        console.error('Transactions error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch transactions'
        });
    }
});

// Get user cards
app.get('/api/wallet/cards', authMiddleware, async (req, res) => {
    try {
        const { data: cards, error } = await supabase
            .from('payment_cards')
            .select('*')
            .eq('user_id', req.userId)
            .order('is_default', { ascending: false })
            .order('created_at', { ascending: false });

        if (error) throw error;

        // Mask card numbers
        const maskedCards = (cards || []).map(card => ({
            ...card,
            card_number: card.card_number.replace(/\d(?=\d{4})/g, '*')
        }));

        res.json({
            success: true,
            cards: maskedCards
        });
    } catch (error) {
        console.error('Get cards error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch cards'
        });
    }
});

// Add payment card
app.post('/api/wallet/cards', authMiddleware, async (req, res) => {
    try {
        const { card_number, card_holder_name, expiry_month, expiry_year, card_type, is_default } = req.body;

        if (!card_number || !card_holder_name || !expiry_month || !expiry_year) {
            return res.status(400).json({
                success: false,
                message: 'All card details are required'
            });
        }

        // Validate expiry date
        const now = new Date();
        const expMonth = parseInt(expiry_month);
        const expYear = parseInt(expiry_year);
        const expDate = new Date(expYear, expMonth - 1);
        
        if (expDate < now) {
            return res.status(400).json({
                success: false,
                message: 'Card has expired'
            });
        }

        // If this is default, unset other defaults
        if (is_default) {
            await supabase
                .from('payment_cards')
                .update({ is_default: false })
                .eq('user_id', req.userId);
        }

        const { data: card, error } = await supabase
            .from('payment_cards')
            .insert([{
                user_id: req.userId,
                card_number: card_number, // In production, encrypt this
                card_holder_name: card_holder_name,
                expiry_month: expiry_month,
                expiry_year: expiry_year,
                card_type: card_type || 'other',
                is_default: is_default || false,
                is_verified: false,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            }])
            .select()
            .single();

        if (error) throw error;

        // Mask card number for response
        card.card_number = card.card_number.replace(/\d(?=\d{4})/g, '*');

        res.status(201).json({
            success: true,
            message: 'Card added successfully',
            card: card
        });
    } catch (error) {
        console.error('Add card error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to add card'
        });
    }
});

// Set default card
app.patch('/api/wallet/cards/:id/default', authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;

        // Verify card belongs to user
        const { data: existing, error: checkError } = await supabase
            .from('payment_cards')
            .select('id')
            .eq('id', id)
            .eq('user_id', req.userId)
            .single();

        if (checkError || !existing) {
            return res.status(404).json({
                success: false,
                message: 'Card not found'
            });
        }

        // Unset all defaults
        await supabase
            .from('payment_cards')
            .update({ is_default: false })
            .eq('user_id', req.userId);

        // Set this as default
        const { data: card, error } = await supabase
            .from('payment_cards')
            .update({
                is_default: true,
                updated_at: new Date().toISOString()
            })
            .eq('id', id)
            .select()
            .single();

        if (error) throw error;

        card.card_number = card.card_number.replace(/\d(?=\d{4})/g, '*');

        res.json({
            success: true,
            message: 'Default card updated',
            card: card
        });
    } catch (error) {
        console.error('Set default card error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update default card'
        });
    }
});

// Delete card
app.delete('/api/wallet/cards/:id', authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;

        const { error } = await supabase
            .from('payment_cards')
            .delete()
            .eq('id', id)
            .eq('user_id', req.userId);

        if (error) throw error;

        res.json({
            success: true,
            message: 'Card deleted successfully'
        });
    } catch (error) {
        console.error('Delete card error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete card'
        });
    }
});

// Create card funding request
app.post('/api/wallet/fund', authMiddleware, async (req, res) => {
    try {
        const { card_id, amount } = req.body;

        if (!card_id || !amount) {
            return res.status(400).json({
                success: false,
                message: 'Card and amount are required'
            });
        }

        const amountNum = parseFloat(amount);
        if (isNaN(amountNum) || amountNum <= 0) {
            return res.status(400).json({
                success: false,
                message: 'Invalid amount'
            });
        }

        // Get min/max funding limits from settings
        const { data: settings } = await supabase
            .from('payment_settings')
            .select('key, value')
            .in('key', ['min_funding_amount', 'max_funding_amount']);

        const minFunding = parseFloat(settings?.find(s => s.key === 'min_funding_amount')?.value || '10');
        const maxFunding = parseFloat(settings?.find(s => s.key === 'max_funding_amount')?.value || '100000');

        if (amountNum < minFunding) {
            return res.status(400).json({
                success: false,
                message: `Minimum funding amount is ₦${minFunding.toFixed(2)}`
            });
        }

        if (amountNum > maxFunding) {
            return res.status(400).json({
                success: false,
                message: `Maximum funding amount is ₦${maxFunding.toFixed(2)}`
            });
        }

        // Verify card belongs to user
        const { data: card, error: cardError } = await supabase
            .from('payment_cards')
            .select('id, is_verified')
            .eq('id', card_id)
            .eq('user_id', req.userId)
            .single();

        if (cardError || !card) {
            return res.status(404).json({
                success: false,
                message: 'Card not found'
            });
        }

        // Create funding request
        const fundingId = uuidv4();
        const { data: funding, error } = await supabase
            .from('card_funding_requests')
            .insert([{
                id: fundingId,
                user_id: req.userId,
                card_id: card_id,
                amount: amountNum,
                status: 'pending',
                requested_at: new Date().toISOString(),
                expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
            }])
            .select()
            .single();

        if (error) throw error;

        // Create notification
        await supabase
            .from('payment_notifications')
            .insert([{
                user_id: req.userId,
                type: 'funding_request',
                title: 'Funding Request Created',
                message: `Your request to fund ₦${amountNum.toFixed(2)} has been submitted and is pending approval.`,
                reference: fundingId,
                created_at: new Date().toISOString()
            }]);

        res.status(201).json({
            success: true,
            message: 'Funding request created',
            request: funding
        });
    } catch (error) {
        console.error('Funding request error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create funding request'
        });
    }
});

// Get user funding requests
app.get('/api/wallet/funding-requests', authMiddleware, async (req, res) => {
    try {
        const { status, limit = 50, offset = 0 } = req.query;

        let query = supabase
            .from('card_funding_requests')
            .select(`
                *,
                card:payment_cards(card_number, card_holder_name, card_type)
            `)
            .eq('user_id', req.userId)
            .order('requested_at', { ascending: false })
            .range(parseInt(offset), parseInt(offset) + parseInt(limit) - 1);

        if (status) {
            query = query.eq('status', status);
        }

        const { data: requests, error } = await query;

        if (error) throw error;

        // Mask card numbers
        const maskedRequests = (requests || []).map(req => ({
            ...req,
            card: req.card ? {
                ...req.card,
                card_number: req.card.card_number.replace(/\d(?=\d{4})/g, '*')
            } : null
        }));

        res.json({
            success: true,
            requests: maskedRequests,
            limit: parseInt(limit),
            offset: parseInt(offset)
        });
    } catch (error) {
        console.error('Get funding requests error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch funding requests'
        });
    }
});

// ===== ADMIN ROUTES =====

// Get all funding requests (admin)
app.get('/api/admin/funding-requests', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { status, limit = 50, offset = 0 } = req.query;

        let query = supabase
            .from('card_funding_requests')
            .select(`
                *,
                user:users(id, name, email, account_number, balance),
                card:payment_cards(card_number, card_holder_name, card_type),
                approved_by_user:users!approved_by(id, name, email)
            `)
            .order('requested_at', { ascending: false })
            .range(parseInt(offset), parseInt(offset) + parseInt(limit) - 1);

        if (status) {
            query = query.eq('status', status);
        }

        const { data: requests, error } = await query;

        if (error) throw error;

        res.json({
            success: true,
            requests: requests || [],
            limit: parseInt(limit),
            offset: parseInt(offset)
        });
    } catch (error) {
        console.error('Admin funding requests error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch funding requests'
        });
    }
});

// Approve funding request (admin)
app.patch('/api/admin/funding-requests/:id/approve', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const { admin_notes } = req.body;

        // Get funding request
        const { data: funding, error: fundingError } = await supabase
            .from('card_funding_requests')
            .select('*')
            .eq('id', id)
            .single();

        if (fundingError || !funding) {
            return res.status(404).json({
                success: false,
                message: 'Funding request not found'
            });
        }

        if (funding.status !== 'pending') {
            return res.status(400).json({
                success: false,
                message: `Request is already ${funding.status}`
            });
        }

        if (new Date(funding.expires_at) < new Date()) {
            return res.status(400).json({
                success: false,
                message: 'Funding request has expired'
            });
        }

        const amount = parseFloat(funding.amount);
        const reference = generateReference();

        // Update user balance
        await updateUserBalance(
            funding.user_id,
            amount,
            'credit',
            `Funding via card - ${reference}`,
            'funding',
            reference,
            null,
            funding.id
        );

        // Update funding request
        const { data: updatedFunding, error: updateError } = await supabase
            .from('card_funding_requests')
            .update({
                status: 'approved',
                admin_notes: admin_notes || null,
                processed_at: new Date().toISOString(),
                approved_by: req.userId
            })
            .eq('id', id)
            .select()
            .single();

        if (updateError) throw updateError;

        // Create notification for user
        await supabase
            .from('payment_notifications')
            .insert([{
                user_id: funding.user_id,
                type: 'funding_approved',
                title: 'Funding Approved ✅',
                message: `Your funding request of ₦${amount.toFixed(2)} has been approved and credited to your wallet.`,
                reference: id,
                created_at: new Date().toISOString()
            }]);

        res.json({
            success: true,
            message: 'Funding request approved',
            request: updatedFunding
        });
    } catch (error) {
        console.error('Approve funding error:', error);
        res.status(500).json({
            success: false,
            message: error.message || 'Failed to approve funding'
        });
    }
});

// Reject funding request (admin)
app.patch('/api/admin/funding-requests/:id/reject', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const { reason } = req.body;

        if (!reason) {
            return res.status(400).json({
                success: false,
                message: 'Rejection reason is required'
            });
        }

        // Get funding request
        const { data: funding, error: fundingError } = await supabase
            .from('card_funding_requests')
            .select('*')
            .eq('id', id)
            .single();

        if (fundingError || !funding) {
            return res.status(404).json({
                success: false,
                message: 'Funding request not found'
            });
        }

        if (funding.status !== 'pending') {
            return res.status(400).json({
                success: false,
                message: `Request is already ${funding.status}`
            });
        }

        // Update funding request
        const { data: updatedFunding, error: updateError } = await supabase
            .from('card_funding_requests')
            .update({
                status: 'rejected',
                reason: reason,
                processed_at: new Date().toISOString(),
                approved_by: req.userId
            })
            .eq('id', id)
            .select()
            .single();

        if (updateError) throw updateError;

        // Create notification for user
        await supabase
            .from('payment_notifications')
            .insert([{
                user_id: funding.user_id,
                type: 'funding_rejected',
                title: 'Funding Rejected ❌',
                message: `Your funding request of ₦${parseFloat(funding.amount).toFixed(2)} was rejected. Reason: ${reason}`,
                reference: id,
                created_at: new Date().toISOString()
            }]);

        res.json({
            success: true,
            message: 'Funding request rejected',
            request: updatedFunding
        });
    } catch (error) {
        console.error('Reject funding error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to reject funding'
        });
    }
});

// Get all users with balance info (admin)
app.get('/api/admin/users/balances', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { data: users, error } = await supabase
            .from('users')
            .select('id, name, email, account_number, balance, account_status, created_at, last_login')
            .order('created_at', { ascending: false });

        if (error) throw error;

        // Get latest ledger for each user
        const usersWithLedger = await Promise.all((users || []).map(async (user) => {
            const { data: ledger } = await supabase
                .from('account_ledger')
                .select('ledger_balance, status, created_at')
                .eq('user_id', user.id)
                .order('created_at', { ascending: false })
                .limit(1);

            return {
                ...user,
                balance: parseFloat(user.balance),
                ledger_balance: ledger && ledger.length > 0 ? parseFloat(ledger[0].ledger_balance) : null,
                ledger_status: ledger && ledger.length > 0 ? ledger[0].status : 'unknown',
                ledger_updated: ledger && ledger.length > 0 ? ledger[0].created_at : null
            };
        }));

        res.json({
            success: true,
            users: usersWithLedger
        });
    } catch (error) {
        console.error('Get users balances error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch users'
        });
    }
});

// Get account ledger discrepancies (admin)
app.get('/api/admin/ledger/discrepancies', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { data: discrepancies, error } = await supabase
            .from('account_ledger')
            .select(`
                *,
                user:users(id, name, email, account_number, balance)
            `)
            .eq('status', 'flagged')
            .order('created_at', { ascending: false });

        if (error) throw error;

        res.json({
            success: true,
            discrepancies: discrepancies || []
        });
    } catch (error) {
        console.error('Get discrepancies error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch discrepancies'
        });
    }
});

// Merge user balance with ledger (admin)
app.patch('/api/admin/ledger/:id/merge', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { id } = req.params;

        const { data: ledger, error: ledgerError } = await supabase
            .from('account_ledger')
            .select('*')
            .eq('id', id)
            .single();

        if (ledgerError || !ledger) {
            return res.status(404).json({
                success: false,
                message: 'Ledger entry not found'
            });
        }

        // Update user balance to match ledger
        const { error: updateError } = await supabase
            .from('users')
            .update({
                balance: ledger.ledger_balance,
                updated_at: new Date().toISOString()
            })
            .eq('id', ledger.user_id);

        if (updateError) throw updateError;

        // Update ledger status
        const { data: updatedLedger, error: statusError } = await supabase
            .from('account_ledger')
            .update({
                status: 'resolved',
                resolved_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            })
            .eq('id', id)
            .select()
            .single();

        if (statusError) throw statusError;

        // Create a new ledger entry with matched balance
        await updateAccountLedger(ledger.user_id);

        // Create notification
        await supabase
            .from('payment_notifications')
            .insert([{
                user_id: ledger.user_id,
                type: 'adjustment',
                title: 'Balance Adjustment',
                message: `Your wallet balance has been adjusted to match the ledger balance of ₦${parseFloat(ledger.ledger_balance).toFixed(2)}.`,
                created_at: new Date().toISOString()
            }]);

        res.json({
            success: true,
            message: 'Balance merged with ledger',
            ledger: updatedLedger
        });
    } catch (error) {
        console.error('Merge ledger error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to merge balance'
        });
    }
});

// Reset user balance to ledger (admin)
app.patch('/api/admin/ledger/:id/reset', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { id } = req.params;

        const { data: ledger, error: ledgerError } = await supabase
            .from('account_ledger')
            .select('*')
            .eq('id', id)
            .single();

        if (ledgerError || !ledger) {
            return res.status(404).json({
                success: false,
                message: 'Ledger entry not found'
            });
        }

        // Reset user balance to ledger balance
        const { error: updateError } = await supabase
            .from('users')
            .update({
                balance: ledger.ledger_balance,
                updated_at: new Date().toISOString()
            })
            .eq('id', ledger.user_id);

        if (updateError) throw updateError;

        // Create adjustment transaction
        const reference = generateReference();
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('balance')
            .eq('id', ledger.user_id)
            .single();

        if (!userError && user) {
            await supabase
                .from('wallet_transactions')
                .insert([{
                    user_id: ledger.user_id,
                    transaction_type: 'adjustment',
                    amount: parseFloat(ledger.ledger_balance) - parseFloat(ledger.actual_balance),
                    balance_before: parseFloat(ledger.actual_balance),
                    balance_after: parseFloat(user.balance),
                    reference: reference,
                    description: `Balance reset to match ledger - ${reference}`,
                    category: 'adjustment',
                    status: 'completed',
                    created_at: new Date().toISOString(),
                    completed_at: new Date().toISOString()
                }]);
        }

        // Update ledger status
        const { data: updatedLedger, error: statusError } = await supabase
            .from('account_ledger')
            .update({
                status: 'resolved',
                resolved_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            })
            .eq('id', id)
            .select()
            .single();

        if (statusError) throw statusError;

        // Create new ledger entry
        await updateAccountLedger(ledger.user_id);

        // Create notification
        await supabase
            .from('payment_notifications')
            .insert([{
                user_id: ledger.user_id,
                type: 'adjustment',
                title: 'Balance Reset',
                message: `Your wallet balance has been reset to ₦${parseFloat(ledger.ledger_balance).toFixed(2)} to match the ledger.`,
                created_at: new Date().toISOString()
            }]);

        res.json({
            success: true,
            message: 'Balance reset to ledger',
            ledger: updatedLedger
        });
    } catch (error) {
        console.error('Reset ledger error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to reset balance'
        });
    }
});

// Get all notifications (user)
app.get('/api/notifications', authMiddleware, async (req, res) => {
    try {
        const { limit = 50, offset = 0, unread_only = false } = req.query;

        let query = supabase
            .from('payment_notifications')
            .select('*')
            .eq('user_id', req.userId)
            .order('created_at', { ascending: false })
            .range(parseInt(offset), parseInt(offset) + parseInt(limit) - 1);

        if (unread_only === 'true') {
            query = query.eq('is_read', false);
        }

        const { data: notifications, error } = await query;

        if (error) throw error;

        const { count, error: countError } = await supabase
            .from('payment_notifications')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', req.userId);

        const { count: unreadCount, error: unreadError } = await supabase
            .from('payment_notifications')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', req.userId)
            .eq('is_read', false);

        res.json({
            success: true,
            notifications: notifications || [],
            total: count || 0,
            unread_count: unreadCount || 0,
            limit: parseInt(limit),
            offset: parseInt(offset)
        });
    } catch (error) {
        console.error('Notifications error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch notifications'
        });
    }
});

// Mark notification as read
app.patch('/api/notifications/:id/read', authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;

        const { error } = await supabase
            .from('payment_notifications')
            .update({
                is_read: true,
                read_at: new Date().toISOString()
            })
            .eq('id', id)
            .eq('user_id', req.userId);

        if (error) throw error;

        res.json({
            success: true,
            message: 'Notification marked as read'
        });
    } catch (error) {
        console.error('Mark notification read error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update notification'
        });
    }
});

// Mark all notifications as read
app.patch('/api/notifications/read-all', authMiddleware, async (req, res) => {
    try {
        const { error } = await supabase
            .from('payment_notifications')
            .update({
                is_read: true,
                read_at: new Date().toISOString()
            })
            .eq('user_id', req.userId)
            .eq('is_read', false);

        if (error) throw error;

        res.json({
            success: true,
            message: 'All notifications marked as read'
        });
    } catch (error) {
        console.error('Mark all read error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update notifications'
        });
    }
});

// Get payment settings (admin)
app.get('/api/admin/payment-settings', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { data: settings, error } = await supabase
            .from('payment_settings')
            .select('*')
            .order('key');

        if (error) throw error;

        res.json({
            success: true,
            settings: settings || []
        });
    } catch (error) {
        console.error('Get settings error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch settings'
        });
    }
});

// Update payment settings (admin)
app.patch('/api/admin/payment-settings', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { settings } = req.body;

        if (!settings || typeof settings !== 'object') {
            return res.status(400).json({
                success: false,
                message: 'Settings object is required'
            });
        }

        const results = [];
        for (const [key, value] of Object.entries(settings)) {
            const { data, error } = await supabase
                .from('payment_settings')
                .update({
                    value: String(value),
                    updated_at: new Date().toISOString(),
                    updated_by: req.userId
                })
                .eq('key', key)
                .select()
                .single();

            if (error) {
                console.error(`Failed to update setting ${key}:`, error);
                results.push({ key, success: false, error: error.message });
            } else {
                results.push({ key, success: true, data });
            }
        }

        res.json({
            success: true,
            message: 'Settings updated',
            results: results
        });
    } catch (error) {
        console.error('Update settings error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update settings'
        });
    }
});

