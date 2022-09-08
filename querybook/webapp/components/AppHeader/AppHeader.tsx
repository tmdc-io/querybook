import React from 'react';
import { UserMenuHeader } from 'components/UserMenu/UserMenuHeader';
import { EnvironmentTopbar } from 'components/EnvironmentAppSidebar/EnvironmentTopbar';

export const AppHeader: React.FunctionComponent = () => {

    return <div className="global-app-header">
        <div
            style={{
                display: 'flex',
                alignItems: 'center',
                cursor: 'pointer',
            }}
        >
            <img
                src={'/querybook/images/dataOS-querybook-logo.svg'}
                width="175"
                className="dataos-app-logo"
                title="Home"
                alt="Home"
                onClick={() => history.push('/')}
            />
            <EnvironmentTopbar />
        </div>
        <div style={{ marginLeft: 'auto' }}>
            <UserMenuHeader />
        </div>
    </div>
};
