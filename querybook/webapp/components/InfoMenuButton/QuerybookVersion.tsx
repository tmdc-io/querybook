import React from 'react';

import { getAppVersion, getAppBuildDate } from 'lib/utils/global';

export const QuerybookVersion: React.FC = () => <span>{getAppVersion()}</span>;
export const QuerybookBuildDate: React.FC = () => (
    <span>{getAppBuildDate()}</span>
);
