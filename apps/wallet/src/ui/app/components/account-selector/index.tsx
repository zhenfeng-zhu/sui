import { useFeature } from '@growthbook/growthbook-react';
import { Popover, Transition } from '@headlessui/react';
import { ChevronDown12, Copy12 } from '@mysten/icons';

import { useMiddleEllipsis } from '../../hooks';
import { useAccounts } from '../../hooks/useAccounts';
import { useActiveAddress } from '../../hooks/useActiveAddress';
import { useCopyToClipboard } from '../../hooks/useCopyToClipboard';
import { ButtonConnectedTo } from '../../shared/button-connected-to';
import { FEATURES } from '_src/shared/experimentation/features';

export function AccountSelector() {
    const allAccounts = useAccounts();
    const activeAddress = useActiveAddress();
    const multiAccountsEnabled = useFeature(FEATURES.WALLET_MULTI_ACCOUNTS).on;
    const activeAddressShort = useMiddleEllipsis(activeAddress);
    const copyToAddress = useCopyToClipboard(activeAddressShort, {
        copySuccessMessage: 'Address copied',
    });
    if (!allAccounts.length) {
        return null;
    }
    if (!multiAccountsEnabled || allAccounts.length === 1) {
        return (
            <ButtonConnectedTo
                text={activeAddressShort}
                onClick={copyToAddress}
                iconRight={
                    <Copy12 className="text-steel hover:text-hero transition" />
                }
                bgOnHover="grey"
            />
        );
    }
    return (
        <Popover className="relative">
            {({ close }) => (
                <>
                    <Popover.Button
                        as={ButtonConnectedTo}
                        text={activeAddressShort}
                        iconRight={<ChevronDown12 />}
                    />
                    <Transition
                        enter="transition duration-100 ease-out"
                        enterFrom="transform scale-95 opacity-0"
                        enterTo="transform scale-100 opacity-100"
                        leave="transition duration-1000 ease-out"
                        leaveFrom="transform scale-100 opacity-100"
                        leaveTo="transform scale-95 opacity-0"
                    >
                        <Popover.Panel className="absolute left-1/2 -translate-x-1/2 w-[55vw] overflow-hidden rounded-md bg-white p-1.25">
                            {JSON.stringify(allAccounts)}
                        </Popover.Panel>
                    </Transition>
                </>
            )}
        </Popover>
    );
}
