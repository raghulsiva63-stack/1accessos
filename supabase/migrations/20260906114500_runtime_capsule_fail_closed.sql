begin;

-- Definitions can be prepared before review, but they cannot be runnable until
-- a reviewed broker explicitly activates them after the global runtime gate.
alter table public.agent_task_capsules alter column status set default 'suspended';

commit;
