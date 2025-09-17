<script lang="ts">
        import { onMount, getContext } from 'svelte';
        import { goto } from '$app/navigation';
        import { WEBUI_NAME, showSidebar, user, mobile } from '$lib/stores';
        import Tooltip from '$lib/components/common/Tooltip.svelte';
        import Sidebar from '$lib/components/icons/Sidebar.svelte';

        const i18n = getContext('i18n');

        let hasAccess = false;
        let initialized = false;

        onMount(() => {
                const unsubscribe = user.subscribe((value) => {
                        if (value !== undefined) {
                                const allowed =
                                        value?.role === 'admin' || (value?.permissions?.workspace?.knowledge ?? false);

                                if (!allowed) {
                                        goto('/');
                                } else {
                                        hasAccess = true;
                                }

                                initialized = true;
                        }
                });

                return () => {
                        unsubscribe();
                };
        });
</script>

<svelte:head>
        <title>
                {$i18n.t('Knowledge Base')} • {$WEBUI_NAME}
        </title>
</svelte:head>

{#if initialized && hasAccess}
        <div
                class=" relative flex flex-col w-full h-screen max-h-[100dvh] transition-width duration-200 ease-in-out {$showSidebar
                        ? 'md:max-w-[calc(100%-260px)]'
                        : ''} max-w-full"
        >
                <nav class="   px-2.5 pt-1.5 backdrop-blur-xl drag-region">
                        <div class=" flex items-center gap-1">
                                {#if $mobile}
                                        <div class="{$showSidebar ? 'md:hidden' : ''} self-center flex flex-none items-center">
                                                <Tooltip
                                                        content={$showSidebar ? $i18n.t('Close Sidebar') : $i18n.t('Open Sidebar')}
                                                        interactive={true}
                                                >
                                                        <button
                                                                id="sidebar-toggle-button"
                                                                class=" cursor-pointer flex rounded-lg hover:bg-gray-100 dark:hover:bg-gray-850 transition cursor-"
                                                                on:click={() => {
                                                                        showSidebar.set(!$showSidebar);
                                                                }}
                                                        >
                                                                <div class=" self-center p-1.5">
                                                                        <Sidebar />
                                                                </div>
                                                        </button>
                                                </Tooltip>
                                        </div>
                                {/if}

                                <div class="ml-2 py-0.5 self-center flex items-center">
                                        <div
                                                class="flex gap-1 scrollbar-none overflow-x-auto w-fit text-center text-sm font-medium bg-transparent py-1 touch-auto pointer-events-auto"
                                        >
                                                <a class="min-w-fit transition" href="/knowledge">
                                                        {$i18n.t('Knowledge Base')}
                                                </a>
                                        </div>
                                </div>
                        </div>
                </nav>

                <div class="  pb-1 px-[18px] flex-1 max-h-full overflow-y-auto" id="knowledge-container">
                        <slot />
                </div>
        </div>
{/if}
